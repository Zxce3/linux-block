/*
 * Copyright (c) 2012 Bryan Schumaker <bjschuma@netapp.com>
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/nfs4_mount.h>
#include <linux/nfs_fs.h>
#include "delegation.h"
#include "internal.h"
#include "nfs4_fs.h"
#include "nfs4idmap.h"
#include "dns_resolve.h"
#include "pnfs.h"
#include "nfs.h"

#define NFSDBG_FACILITY		NFSDBG_VFS

static int nfs4_write_inode(struct inode *inode, struct writeback_control *wbc);
static void nfs4_evict_inode(struct inode *inode);

static const struct super_operations nfs4_sops = {
	.alloc_inode	= nfs_alloc_inode,
	.destroy_inode	= nfs_destroy_inode,
	.write_inode	= nfs4_write_inode,
	.drop_inode	= nfs_drop_inode,
	.statfs		= nfs_statfs,
	.evict_inode	= nfs4_evict_inode,
	.umount_begin	= nfs_umount_begin,
	.show_options	= nfs_show_options,
	.show_devname	= nfs_show_devname,
	.show_path	= nfs_show_path,
	.show_stats	= nfs_show_stats,
};

struct nfs_subversion nfs_v4 = {
	.owner		= THIS_MODULE,
	.nfs_fs		= &nfs4_fs_type,
	.rpc_vers	= &nfs_version4,
	.rpc_ops	= &nfs_v4_clientops,
	.sops		= &nfs4_sops,
	.xattr		= nfs4_xattr_handlers,
};

static int nfs4_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int ret = nfs_write_inode(inode, wbc);

	if (ret == 0)
		ret = pnfs_layoutcommit_inode(inode,
				wbc->sync_mode == WB_SYNC_ALL);
	return ret;
}

/*
 * Clean out any remaining NFSv4 state that might be left over due
 * to open() calls that passed nfs_atomic_lookup, but failed to call
 * nfs_open().
 */
static void nfs4_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	/* If we are holding a delegation, return it! */
	nfs_inode_return_delegation_noreclaim(inode);
	/* Note that above delegreturn would trigger pnfs return-on-close */
	pnfs_return_layout(inode);
	pnfs_destroy_layout(NFS_I(inode));
	/* First call standard NFS clear_inode() code */
	nfs_clear_inode(inode);
}

/*
 * Get the superblock for the NFS4 root partition
 */
static int nfs4_get_remote_tree(struct fs_context *fc)
{
	struct nfs_fs_context *ctx = nfs_fc2context(fc);
	struct nfs_server *server;

	ctx->set_security = nfs_set_sb_security;

	/* Get a volume representation */
	server = nfs4_create_server(fc);
	if (IS_ERR(server))
		return PTR_ERR(server);

	return nfs_get_tree_common(server, fc);
}

/*
 * Create a mount for the root of the server.  We copy the mount context we
 * have for the parameters and set its hostname, path and type.
 */
static struct vfsmount *nfs_do_root_mount(struct fs_context *fc,
					  const char *hostname,
					  enum nfs_mount_type type)
{
	struct nfs_fs_context *root_ctx;
	struct fs_context *root_fc;
	struct vfsmount *root_mnt;
	size_t len;
	int ret;

	struct fs_parameter param = {
		.key	= "source",
		.type	= fs_value_is_string,
		.dirfd	= -1,
	};

	root_fc = vfs_dup_fs_context(fc, FS_CONTEXT_FOR_ROOT_MOUNT);
	if (IS_ERR(root_fc))
		return ERR_CAST(root_fc);
	kfree(root_fc->source);
	root_fc->source = NULL;

	root_ctx = nfs_fc2context(root_fc);
	root_ctx->mount_type = type;
	root_ctx->nfs_server.export_path = (char *)nfs_slash;

	len = strlen(hostname) + 5;
	root_mnt = ERR_PTR(-ENOMEM);
	param.string = kmalloc(len, GFP_KERNEL);
	if (param.string == NULL)
		goto out_fc;

	/* Does hostname needs to be enclosed in brackets? */
	if (strchr(hostname, ':'))
		param.size = snprintf(param.string, len, "[%s]:/", hostname);
	else
		param.size = snprintf(param.string, len, "%s:/", hostname);
	ret = vfs_parse_fs_param(root_fc, &param);
	kfree(param.string);
	if (ret < 0) {
		root_mnt = ERR_PTR(ret);
		goto out_fc;
	}

	ret = vfs_get_tree(root_fc);
	if (ret < 0) {
		root_mnt = ERR_PTR(ret);
		goto out_fc;
	}

	root_mnt = vfs_create_mount(root_fc, 0);
out_fc:
	put_fs_context(root_fc);
	return root_mnt;
}

struct nfs_referral_count {
	struct list_head list;
	const struct task_struct *task;
	unsigned int referral_count;
};

static LIST_HEAD(nfs_referral_count_list);
static DEFINE_SPINLOCK(nfs_referral_count_list_lock);

static struct nfs_referral_count *nfs_find_referral_count(void)
{
	struct nfs_referral_count *p;

	list_for_each_entry(p, &nfs_referral_count_list, list) {
		if (p->task == current)
			return p;
	}
	return NULL;
}

#define NFS_MAX_NESTED_REFERRALS 2

static int nfs_referral_loop_protect(void)
{
	struct nfs_referral_count *p, *new;
	int ret = -ENOMEM;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		goto out;
	new->task = current;
	new->referral_count = 1;

	ret = 0;
	spin_lock(&nfs_referral_count_list_lock);
	p = nfs_find_referral_count();
	if (p != NULL) {
		if (p->referral_count >= NFS_MAX_NESTED_REFERRALS)
			ret = -ELOOP;
		else
			p->referral_count++;
	} else {
		list_add(&new->list, &nfs_referral_count_list);
		new = NULL;
	}
	spin_unlock(&nfs_referral_count_list_lock);
	kfree(new);
out:
	return ret;
}

static void nfs_referral_loop_unprotect(void)
{
	struct nfs_referral_count *p;

	spin_lock(&nfs_referral_count_list_lock);
	p = nfs_find_referral_count();
	p->referral_count--;
	if (p->referral_count == 0)
		list_del(&p->list);
	else
		p = NULL;
	spin_unlock(&nfs_referral_count_list_lock);
	kfree(p);
}

static struct dentry *nfs_follow_remote_path(struct vfsmount *root_mnt,
		const char *export_path)
{
	struct dentry *dentry;
	int err;

	if (IS_ERR(root_mnt))
		return ERR_CAST(root_mnt);

	err = nfs_referral_loop_protect();
	if (err) {
		mntput(root_mnt);
		return ERR_PTR(err);
	}

	dentry = mount_subtree(root_mnt, export_path);
	nfs_referral_loop_unprotect();

	return dentry;
}

int nfs4_try_get_tree(struct fs_context *fc)
{
	struct nfs_fs_context *ctx = nfs_fc2context(fc);
	struct vfsmount *root_mnt;
	struct dentry *root;

	dfprintk(MOUNT, "--> nfs4_try_get_tree()\n");

	/* We create a mount for the server's root, walk to the requested
	 * location and then create another mount for that.
	 */
	root_mnt = nfs_do_root_mount(fc, ctx->nfs_server.hostname,
				     NFS4_MOUNT_REMOTE);
	if (IS_ERR(root_mnt))
		return PTR_ERR(root_mnt);

	root = nfs_follow_remote_path(root_mnt, ctx->nfs_server.export_path);
	if (IS_ERR(root)) {
		nfs_errorf(fc, "NFS4: Couldn't follow remote path");
		dfprintk(MOUNT, "<-- nfs4_try_mount() = %ld [error]\n",
			 PTR_ERR(root));
		return PTR_ERR(root);
	}

	fc->root = root;
	dfprintk(MOUNT, "<-- nfs4_try_get_tree() = 0\n");
	return 0;
}

static int nfs4_get_remote_referral_tree(struct fs_context *fc)
{
	struct nfs_fs_context *ctx = nfs_fc2context(fc);
	struct nfs_server *server;

	dprintk("--> nfs4_get_remote_referral_tree()\n");

	ctx->set_security = nfs_clone_sb_security;

	if (!ctx->clone_data.cloned)
		return -EINVAL;

	/* create a new volume representation */
	server = nfs4_create_referral_server(fc);
	if (IS_ERR(server))
		return PTR_ERR(server);

	return nfs_get_tree_common(server, fc);
}

/*
 * Create an NFS4 server record on referral traversal
 */
static int nfs4_get_referral_tree(struct fs_context *fc)
{
	struct nfs_fs_context *ctx = nfs_fc2context(fc);
	struct vfsmount *root_mnt;
	struct dentry *root;

	dprintk("--> nfs4_referral_mount()\n");

	root_mnt = nfs_do_root_mount(fc, ctx->nfs_server.hostname,
				     NFS4_MOUNT_REMOTE_REFERRAL);

	root = nfs_follow_remote_path(root_mnt, ctx->nfs_server.export_path);
	if (IS_ERR(root)) {
		nfs_errorf(fc, "NFS4: Couldn't follow remote path");
		dfprintk(MOUNT, "<-- nfs4_referral_mount() = %ld [error]\n",
			 PTR_ERR(root));
		return PTR_ERR(root);
	}

	fc->root = root;
	dfprintk(MOUNT, "<-- nfs4_get_referral_tree() = 0\n");
	return 0;
}

/*
 * Handle special NFS4 mount types.
 */
int nfs4_get_tree(struct fs_context *fc)
{
	struct nfs_fs_context *ctx = nfs_fc2context(fc);

	switch (ctx->mount_type) {
	case NFS4_MOUNT_REMOTE:
		return nfs4_get_remote_tree(fc);

	case NFS4_MOUNT_REFERRAL:
		return nfs4_get_referral_tree(fc);

	case NFS4_MOUNT_REMOTE_REFERRAL:
		return nfs4_get_remote_referral_tree(fc);

	default:
		return 1;
	}
}

static int __init init_nfs_v4(void)
{
	int err;

	err = nfs_dns_resolver_init();
	if (err)
		goto out;

	err = nfs_idmap_init();
	if (err)
		goto out1;

	err = nfs4_register_sysctl();
	if (err)
		goto out2;

	register_nfs_version(&nfs_v4);
	return 0;
out2:
	nfs_idmap_quit();
out1:
	nfs_dns_resolver_destroy();
out:
	return err;
}

static void __exit exit_nfs_v4(void)
{
	/* Not called in the _init(), conditionally loaded */
	nfs4_pnfs_v3_ds_connect_unload();

	unregister_nfs_version(&nfs_v4);
	nfs4_unregister_sysctl();
	nfs_idmap_quit();
	nfs_dns_resolver_destroy();
}

MODULE_LICENSE("GPL");

module_init(init_nfs_v4);
module_exit(exit_nfs_v4);
