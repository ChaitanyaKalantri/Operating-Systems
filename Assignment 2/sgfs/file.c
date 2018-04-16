/*
 * Copyright (c) 1998-2015 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2015 Stony Brook University
 * Copyright (c) 2003-2015 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/path.h>
#include <linux/err.h>
#include <crypto/hash.h>
#include<crypto/skcipher.h>
#include<linux/cred.h>


#include "sgfs.h"
#define SGFS_IOCTL _IOR(100, 0, char*)
extern char key_val[20];
struct dir_context *global_ctx;


static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void){
    return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}
static const u8 *aes_iv = "cephsageyudagreg";

static void printData(unsigned char *src, int len, char *name)
{
        int i=0;
        printk("Printing for %s  and len %d\n", name, len);
        for (i=0; i < len; i++) {
                printk("%x ", src[i]);
        }
        printk("\n");

}


int ceph_aes_decrypt(const void *key, int key_len, void *dst, size_t *dst_len,
                      const void *src, size_t src_len){
    struct scatterlist sg_in[1], sg_out[2];
    struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
    struct blkcipher_desc desc = { .tfm = tfm };
    char pad[16];
    void *iv;
    int ivsize;
    int ret;
    int last_byte;
    
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    
    crypto_blkcipher_setkey((void *)tfm, key, key_len);
    sg_init_table(sg_in, 1);
    sg_init_table(sg_out, 2);
    sg_set_buf(sg_in, src, src_len);
    sg_set_buf(&sg_out[0], dst, *dst_len);
    sg_set_buf(&sg_out[1], pad, sizeof(pad));

    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm);
    
    memcpy(iv, aes_iv, ivsize); 

    ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
    crypto_free_blkcipher(tfm);
    if (ret < 0) {
        pr_err("ceph_aes_decrypt failed %d\n", ret);
        return ret;
    }
         
    if (src_len <= *dst_len)
        last_byte = ((char *)dst)[src_len - 1];
    else
        last_byte = pad[src_len - *dst_len - 1];

    if (last_byte <= 16 && src_len >= last_byte) {
        *dst_len = src_len - last_byte;
    } 
    else {
        pr_err("ceph_aes_decrypt got bad padding %d on src len %d\n",
                    last_byte, (int)src_len);
        return -EPERM;  /* bad padding */
    }
    
    return 0;
}


int sgfs_undelete(struct inode *dir, struct dentry *dentry)
{
        char k_keybuf[30]; // = "ENCRYPT";
        int flag = 0, count = 5, i, len = 0;
        if(strlen(key_val) == 0)
        {
                flag = 1;
                printk("The keyval is NULL\n");
        }
        else
        {
                strcpy(k_keybuf, key_val);
        }
	
	strcpy(k_keybuf, key_val);

        char *k_tempdst = NULL ;
        char *k_temp2dst = NULL ;
        size_t k_dstlen; 
	//k_dstlen = kmalloc(sizeof(ssize_t), GFP_KERNEL);
        
        int keylen = strlen(k_keybuf);
        int ret = 0, err=0;
        char *filp0_buf = NULL;
        struct file *filp1 = NULL, *filp0 = NULL;
        int f_readBytes, f_readLen;
        mm_segment_t oldfs;
        loff_t f_readOffset = 0, f_writeOffset = 0;
        
        char *test = NULL, *p = NULL, *pathname = NULL, *original = NULL;

        struct dentry *lower_dentry = NULL;
        struct inode *lower_dir_inode = sgfs_lower_inode(dir);
        struct dentry *lower_dir_dentry = NULL;
        struct path lower_path;

        sgfs_get_lower_path(dentry, &lower_path);
        lower_dentry = lower_path.dentry;
        dget(lower_dentry);

	//k_dstlen = (size_t) kmalloc(sizeof(ssize_t), GFP_KERNEL);

        k_tempdst = kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!k_tempdst)
        {
                printk("Error\n");
                return err;
        }

	test = kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!test)
        {
                printk("Error\n");
                return err;
        }

        k_temp2dst = kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!k_temp2dst)
        {
                printk("Error\n");

return err;
        }

        pathname = kmalloc(PATH_MAX+11, GFP_KERNEL);
        if (!pathname)
        {
                printk("Error\n");
                return err;
        }
        p = d_path(&lower_path, pathname, PATH_MAX+11);
        if (IS_ERR(p))
        { /* Should never happen since we send PATH_MAX */
                kfree(pathname);
                return err;
        }
        printk("lower path absolute %s\n",p);

	printk("lower_dentry->d_iname is %s\n", lower_dentry->d_name.name);
	//strcpy(test, lower_dentry->d_iname);
	//printk("lower_dentry->d_iname is %s\n", test);

	strncpy(test, lower_dentry->d_name.name + 17, strlen(lower_dentry->d_name.name)-26);
	printk("lower_dentry->d_iname is %s\n", test);	

        original= kmalloc(PATH_MAX,GFP_KERNEL);
        if(!original)
                goto EXIT;

        strcpy(original,p);

        //strcat(p, ".enc");

	for(i=0; original[i] && count > 0; i++)
        {
                if(original[i] == '-')
                    count--;
                len++;
        }

	printk("%d\n", len);
        strcpy(p, original+len);
        printk(" p = %s\n", p);
        
        p[strlen(p)-6] = 0;	

        filp0 = filp_open(original, O_RDONLY, 0664);
        if(!filp0 || IS_ERR(filp0))
        {
                err = -ENOENT;
                goto EXIT;
        }

        filp1 = filp_open(p, O_CREAT|O_WRONLY, 0664);
        if(!filp1 || IS_ERR(filp1))
        {
                err = -ENOENT;
                goto EXIT;
        }

        filp0_buf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);
        if (!filp0_buf){
                printk("No memory for file buffer 1\n");
                err = -ENOMEM;
		goto EXIT;
        }

        oldfs = get_fs();
        set_fs(get_ds());
        f_readLen = filp0->f_inode->i_size;
        printk("Size of the fReadLen is %d \n", f_readLen);

        while(1)
        {
                f_readBytes = vfs_read(filp0, filp0_buf, PAGE_SIZE, &f_readOffset);
                if (f_readBytes < 0)
                {
                        printk("No data\n");
                        set_fs(oldfs);
                        goto EXIT;
                }
                else if(f_readBytes == 0)
                {
                        goto EXIT_NEW;
                }
                else
                {
	        k_dstlen = f_readBytes;			
                //printk("The data read is %s\n", filp0_buf);
		if(flag == 0)
	{
		ret = ceph_aes_decrypt(k_keybuf, keylen, k_tempdst, &k_dstlen, filp0_buf, f_readBytes);
        //printk("%d\n",k_dstlen);

        //printData(k_tempdst, k_dstlen, "k_tempdst");

        if(ret < 0)
           {
                set_fs(oldfs);
                ret = -EPERM;
                goto EXIT;
            }
	
	//vfs_write(filp1, filp0_buf, f_readBytes, &filp1->f_pos);
	
        ret = vfs_write(filp1, k_tempdst, k_dstlen, &f_writeOffset);
	if (ret < 0)
           {
                set_fs(oldfs);
                ret = -EPERM;
                goto out;

           }
	}
	else if(flag == 1)
	{
		ret = vfs_write(filp1, filp0_buf, f_readBytes, &f_writeOffset);
                if (ret < 0)
                {
                        set_fs(oldfs);
                        ret = -EPERM;
                        goto out;
                }
	}
	
	}
    }
	EXIT_NEW:
	
        set_fs(oldfs);
        lower_dir_dentry = lock_parent(lower_dentry);
        printk("Lower_dir_entry is %p\n", lower_dir_dentry);

        if(filp0 != NULL)
                filp_close(filp0, NULL);
        if(filp1 != NULL)
                filp_close(filp1, NULL);

        printk("lower_dentry: %s \n lower_dir_inode: %s", lower_dentry->d_iname);
        err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
        printk("I have completed unlinking\n");


        if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
                err = 0;
        if (err)
                goto out;
        fsstack_copy_attr_times(dir, lower_dir_inode);
        fsstack_copy_inode_size(dir, lower_dir_inode);
        set_nlink(d_inode(dentry),
                          sgfs_lower_inode(d_inode(dentry))->i_nlink);
        d_inode(dentry)->i_ctime = dir->i_ctime;
        d_drop(dentry); 

	out:
        printk("Above unlock_dir %p\n", lower_dir_dentry);

        unlock_dir(lower_dir_dentry);
        printk("Above dput %p\n", lower_dentry);
        dput(lower_dentry);
        printk("Above sgfs_put_lower_path %p\n", dentry);
        sgfs_put_lower_path(dentry, &lower_path);
        printk("Above EXIT\n");

        EXIT:
        if(filp0 != NULL)
                filp_close(filp0, NULL);
        if(filp1 != NULL)
                filp_close(filp1, NULL);	
	if(filp0_buf != NULL)
                kfree(filp0_buf);

	return err;
}

static ssize_t sgfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t sgfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

static int actor_helper(struct dir_context *ctx,const char *name, int len, loff_t off, u64 x, unsigned int d_type )
{
	char *find, *temp_name;
	const struct cred *credTemp = current_cred();
	char *uid_t;

	temp_name = (char *) kmalloc(PAGE_SIZE, __GFP_REPEAT);
	strcpy(temp_name, name);
	printk("temp_name is %s\n", temp_name);	
	
	//char *s = "some/very/big/string";


	/*if(strlen(temp_name) >= 3)	
	{
		last = strrchr(temp_name, '-');
		if(last == NULL)
		     return 0;
	}*/

	if(strlen(temp_name) < 3){
		 return (*global_ctx->actor)(global_ctx, name, len, off, x, d_type);
	}

	char *last = strrchr(temp_name, '-');

	if (last != NULL) {
    	printk("Last token: '%s'\n", last+1);
	}
	
	find = (char *) kmalloc(PAGE_SIZE, __GFP_REPEAT);
	strcpy(find, last+1);
	//strcpy(last, last+1);
	//strncpy(temp_name, last, strlen(last)-4);
	//printk("AFTER Last token: '%s'\n", temp_name);
	/*
	if(strlen(temp_name) >= 3)
	{
		while((find = strsep(&temp_name, "-")) != NULL)
		{	
			break;	// The required ans is found, then break
		}
	}
	*/

	//printk("AFTER temp_name is %s\n", temp_name);
	
	uid_t = (char *) kmalloc(PAGE_SIZE, __GFP_REPEAT);
	
	snprintf(uid_t, PAGE_SIZE, "%d", credTemp->uid.val);

	printk("uid_t = %s \t last = %s \n", uid_t, find);
	
	//strncpy(last, find, strlen(uid_t));

	if(strcmp(uid_t, find) == 0 )
	{
		return (*global_ctx->actor)(global_ctx, name, len, off, x, d_type);
	}
	else
	{
		return 0;
	}

	//if(strcmp(get_current_user()->uid, file(name) ka id))
	//	return old_dir->actor(old_dir, name, len, off, x, y);

}


static int sgfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct dir_context* temp_ctx;	

	struct dir_context new_dir = {.actor = &actor_helper, .pos = ctx->pos};
	temp_ctx = &new_dir;
	global_ctx = ctx;
	
	lower_file = sgfs_lower_file(file);
	
	if(strcmp(lower_file->f_path.dentry->d_iname, ".sg") == 0)
	{
		err = iterate_dir(lower_file, temp_ctx);
	}
	else
		err = iterate_dir(lower_file, ctx);

	//lower_file = sgfs_lower_file(file);
	//err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

static long sgfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;
	struct inode *inode;
	struct dentry *dentry;
	printk("I am in the sgfs_unlocked\n");	
	//printk("Arg is %s \t Command is %d", arg, cmd);
	
	
	inode = file->f_path.dentry->d_parent->d_inode;
	dentry = file->f_path.dentry;
	
	switch(cmd)
	{
	case SGFS_IOCTL:
		sgfs_undelete(inode, dentry);
		return 0;
	default:
		sgfs_unlink(inode, dentry);
		return 0;
	}
	printk("Completed Unlink\n");	
	
	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long sgfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int sgfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = sgfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "sgfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!SGFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "sgfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &sgfs_vm_ops;

	file->f_mapping->a_ops = &sgfs_aops; /* set our aops */
	if (!SGFS_F(file)->lower_vm_ops) /* save for our ->fault */
		SGFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int sgfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sgfs_file_info), GFP_KERNEL);
	if (!SGFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sgfs's file struct to lower's */
	sgfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sgfs_lower_file(file);
		if (lower_file) {
			sgfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sgfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SGFS_F(file));
	else
		fsstack_copy_attr_all(inode, sgfs_lower_inode(inode));
out_err:
	return err;
}

static int sgfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sgfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);
	if (lower_file) {
		sgfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SGFS_F(file));
	return 0;
}

static int sgfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sgfs_lower_file(file);
	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sgfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sgfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sgfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sgfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sgfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Sgfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sgfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Sgfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
sgfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sgfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sgfs_read,
	.write		= sgfs_write,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.mmap		= sgfs_mmap,
	.open		= sgfs_open,
	.flush		= sgfs_flush,
	.release	= sgfs_file_release,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
	.read_iter	= sgfs_read_iter,
	.write_iter	= sgfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sgfs_dir_fops = {
	.llseek		= sgfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sgfs_readdir,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.open		= sgfs_open,
	.release	= sgfs_file_release,
	.flush		= sgfs_flush,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
};
