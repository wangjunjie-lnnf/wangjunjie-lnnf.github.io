---
layout: post
title:  "kernel之vfs"
date:   2023-03-05 10:22:07 +0000
categories: jekyll
tags: kernel vfs
---

# vfs

## 核心数据结构

vfs核心数据结构及其关系
![vfs核心数据结构及其关系](/assets/images/2023-03-05/vfs.png)

### file_system_type

`file_system_type`表示一种特定的文件系统，所有的文件系统都注册在注册表中

```c
// fs注册表
static struct file_system_type *file_systems;

struct file_system_type {
    const char *name;
    int fs_flags;
    // 创建fs_context
    int (*init_fs_context)(struct fs_context *);
    struct dentry *(*mount) (struct file_system_type *, int, const char *, void *);
    void (*kill_sb) (struct super_block *);
    // 单链表结构
    struct file_system_type * next;
}

// 根据fs名称匹配注册的fs
static struct file_system_type **find_filesystem(const char *name, unsigned len)
{
    struct file_system_type **p;
    for (p = &file_systems; *p; p = &(*p)->next)
        if (strncmp((*p)->name, name, len) == 0 && !(*p)->name[len])
            break;
    return p;
}
```

### super_block

`super_block`是一个fs的最核心的数据结构，`ext4`之类的基于磁盘的fs会持久化`super_block`

```c
struct super_block {
    dev_t            s_dev;
    /* block size */
    unsigned long        s_blocksize;
    /* Max file size */
    loff_t            s_maxbytes;    
    struct file_system_type    *s_type;
    /* inode相关function */
    const struct super_operations    *s_op;
    unsigned long        s_magic;
    /* root dir */
    struct dentry        *s_root;
    struct block_device    *s_bdev;
    /* default d_op for dentries */
    struct dentry_operations *s_d_op; 
}
```

`super_block`在系统调用`mount`时创建，创建过程如下：

```c
int do_new_mount(struct path *path, const char *fstype, int sb_flags,
            int mnt_flags, const char *name, void *data)
{
    // 从注册表中查找fs
    struct file_system_type *type = get_fs_type(fstype);

    struct fs_context *fc = fs_context_for_mount(type, sb_flags);
    {
        fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL_ACCOUNT);
        fc->fs_type    = get_filesystem(fs_type);
        init_fs_context = fc->fs_type->init_fs_context;
        if (!init_fs_context)
            init_fs_context = legacy_init_fs_context;

        // 初始化fs_context
        init_fs_context(fc);
    }

    vfs_get_tree(fc);
    {
        // 初始化root和super_block
        fc->ops->get_tree(fc);
    }
}
```

### inode

`inode`表示fs中的一个文件或目录，`ext4`之类的基于磁盘的fs会持久化`inode`

```c
struct inode {
    umode_t            i_mode;
    unsigned short    i_opflags;
    kuid_t            i_uid;
    kgid_t            i_gid;
    unsigned int    i_flags;

    // 从root继承
    const struct inode_operations    *i_op;
    struct super_block    *i_sb;
    struct address_space    *i_mapping;

    dev_t            i_rdev;
    loff_t            i_size;

    struct timespec64    i_atime;
    struct timespec64    i_mtime;
    struct timespec64    i_ctime;

    union {
        // 从root继承
        const struct file_operations    *i_fop;
        void (*free_inode)(struct inode *);
    };
}
```

`inode`在系统调用`open`时通过参数`O_CREAT`创建

```c
struct dentry *lookup_open(struct nameidata *nd, struct file *file,
                  const struct open_flags *op, bool got_write) {
    if (!dentry->d_inode && (open_flag & O_CREAT)) {
        file->f_mode |= FMODE_CREATED;
        
        // 创建文件
        dir_inode->i_op->create(mnt_userns, dir_inode, dentry, mode, open_flag & O_EXCL);
    }
}
```

### dentry

`dentry`表示一个文件或目录，不会持久化到磁盘

```c
struct dentry {
    struct dentry *d_parent;
    struct qstr d_name;
    struct inode *d_inode;
    const struct dentry_operations *d_op;
    struct super_block *d_sb;
}
```

`dentry`在系统调用`open`时创建

```c
struct dentry *d_alloc_parallel(struct dentry *parent,
                const struct qstr *name,
                wait_queue_head_t *wq)
{
    struct dentry *new = d_alloc(parent, name);
    {
        struct dentry *dentry = __d_alloc(parent->d_sb, name);
        {
            dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
            dentry->d_inode = NULL;
            dentry->d_parent = dentry;
            dentry->d_sb = sb;
            dentry->d_op = NULL;
            d_set_d_op(dentry, dentry->d_sb->s_d_op);
        }
        dentry->d_parent = parent;
        list_add(&dentry->d_child, &parent->d_subdirs);
    }
}
```

### vfsmount

`vfsmount`表示挂载点信息

```c
// mount注册表
static struct hlist_head *mount_hashtable;
static struct hlist_head *mountpoint_hashtable;

struct vfsmount {
    struct dentry *mnt_root;
    struct super_block *mnt_sb;
    int mnt_flags;
    struct user_namespace *mnt_userns;
}

static inline struct hlist_head *m_hash(struct vfsmount *mnt, struct dentry *dentry)
{
    // 根据(mnt/dentry)计算hash
    unsigned long tmp = ((unsigned long)mnt / L1_CACHE_BYTES);
    tmp += ((unsigned long)dentry / L1_CACHE_BYTES);
    tmp = tmp + (tmp >> m_hash_shift);
    return &mount_hashtable[tmp & m_hash_mask];
}

// 查找
struct mount *__lookup_mnt(struct vfsmount *mnt, struct dentry *dentry)
{
    struct hlist_head *head = m_hash(mnt, dentry);
    struct mount *p;

    hlist_for_each_entry_rcu(p, head, mnt_hash)
        if (&p->mnt_parent->mnt == mnt && p->mnt_mountpoint == dentry)
            return p;
    return NULL;
}

// 注册
static void __attach_mnt(struct mount *mnt, struct mount *parent)
{
    hlist_add_head_rcu(&mnt->mnt_hash,
               m_hash(&parent->mnt, mnt->mnt_mountpoint));
    list_add_tail(&mnt->mnt_child, &parent->mnt_mounts);
}

```

`vfsmount`在系统调用`mount`时创建

```c
struct vfsmount *vfs_create_mount(struct fs_context *fc)
{
    struct mount *mnt;

    mnt = alloc_vfsmnt(fc->source ?: "none");

    atomic_inc(&fc->root->d_sb->s_active);
    mnt->mnt.mnt_sb        = fc->root->d_sb;
    mnt->mnt.mnt_root    = dget(fc->root);
    mnt->mnt_mountpoint    = mnt->mnt.mnt_root;
    mnt->mnt_parent        = mnt;

    lock_mount_hash();
    list_add_tail(&mnt->mnt_instance, &mnt->mnt.mnt_sb->s_mounts);
    unlock_mount_hash();
    return &mnt->mnt;
}
```

### file

`file`表示一个打开的文件

```c
struct file {
    struct path        f_path;
    struct inode        *f_inode;
    const struct file_operations    *f_op;
    struct address_space    *f_mapping;
}
```

`file`在系统调用`open`时创建

```c
struct file *path_openat(struct nameidata *nd,
            const struct open_flags *op, unsigned flags)
{
    struct file *file = alloc_empty_file(op->open_flag, current_cred());
    do_open(nd, file, op);
    {
        vfs_open(&nd->path, file);
        {
            file->f_path = *path;
            return do_dentry_open(file, d_backing_inode(path->dentry), NULL);
            {
                f->f_inode = inode;
                f->f_mapping = inode->i_mapping;
                f->f_op = fops_get(inode->i_fop);
                f->f_op->open(inode, f);
            }
        }
    }
}
```

## 系统调用

### mount

```c
long do_mount(const char *dev_name, const char __user *dir_name,
        const char *type_page, unsigned long flags, void *data_page)
{
    struct path path;
    // 查找挂载路径
    user_path_at(AT_FDCWD, dir_name, LOOKUP_FOLLOW, &path);
    path_mount(dev_name, &path, type_page, flags, data_page);
    {
        do_new_mount(path, type_page, sb_flags, mnt_flags, dev_name, data_page);
        {
            // 从注册表中查找fs
            struct file_system_type *type = get_fs_type(fstype);
            struct fs_context *fc = fs_context_for_mount(type, sb_flags);
            {
                fc = kzalloc(sizeof(struct fs_context), GFP_KERNEL_ACCOUNT);
                fc->sb_flags    = sb_flags;
                fc->sb_flags_mask = sb_flags_mask;
                fc->fs_type    = get_filesystem(fs_type);

                // 初始化fc
                init_fs_context = fc->fs_type->init_fs_context;
                if (!init_fs_context)
                    init_fs_context = legacy_init_fs_context;

                init_fs_context(fc);
            }

            // 创建super_block和root
            vfs_get_tree(fc);
            {
                fc->ops->get_tree(fc);
            }

            // 添加到注册表
            do_new_mount_fc(fc, path, mnt_flags);
            {
                struct vfsmount *mnt = vfs_create_mount(fc);
                {
                    mnt = alloc_vfsmnt(fc->source ?: "none");
                    mnt->mnt.mnt_sb        = fc->root->d_sb;
                    mnt->mnt.mnt_root    = dget(fc->root);
                    mnt->mnt_mountpoint    = mnt->mnt.mnt_root;
                    mnt->mnt_parent        = mnt;
                }

                struct mountpoint *mp = lock_mount(mountpoint);
                {
                    mnt = lookup_mnt(path);
                    if (likely(!mnt)) {
                        struct mountpoint *mp = get_mountpoint(dentry);
                        {
                            struct mountpoint *new = kmalloc(sizeof(struct mountpoint), GFP_KERNEL);
                            new->m_dentry = dget(dentry);
                            new->m_count = 1;
                            // mountpoint加入注册表
                            hlist_add_head(&new->m_hash, mp_hash(dentry));
                        }
                    }
                }

                do_add_mount(real_mount(mnt), mp, mountpoint, mnt_flags);
                {
                    graft_tree(newmnt, parent, mp);
                    {
                        attach_recursive_mnt(mnt, p, mp, false);
                        {
                            mnt_set_mountpoint(dest_mnt, dest_mp, source_mnt);
                            commit_tree(source_mnt);
                            {
                                // vfsmount添加到注册表
                                __attach_mnt(mnt, parent);
                            }
                        }
                    }
                }
            }
        }
    }
}
```

### open

```c
long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct open_how how = build_open_how(flags, mode);
    return do_sys_openat2(dfd, filename, &how);
    {
        // 查找空闲fd
        int fd = get_unused_fd_flags(how->flags);
        {
            struct files_struct *files = current->files;
            struct fdtable *fdt = files_fdtable(files);
            int fd = find_next_fd(fdt, fd);
        }

        struct file *f = do_filp_open(dfd, tmp, &op);
        {
            // 内部包含一个stack结构，用于追踪链接
            struct nameidata nd;
            set_nameidata(&nd, dfd, pathname, NULL);

            struct file *filp = path_openat(&nd, op, flags | LOOKUP_RCU);
            {
                struct file *file = alloc_empty_file(op->open_flag, current_cred());
                // 初始化查找的起点
                const char *s = path_init(nd, flags);
                {
                    // 绝对路径从root开始
                    if (*s == '/') {
                        nd_jump_root(nd);
                        {
                            struct fs_struct *fs = current->fs;
                            nd->root = fs->root;
                            nd->path = nd->root;
                            nd->inode = nd->path.dentry->d_inode;
                        }
                        return s;
                    }

                    // 相对于工作目录
                    if (nd->dfd == AT_FDCWD) {
                        get_fs_pwd(current->fs, &nd->path);
                        nd->inode = nd->path.dentry->d_inode;
                    } else {
                        // 相对于任意目录
                        struct fd f = fdget_raw(nd->dfd);
                        struct dentry *dentry = f.file->f_path.dentry;
                        nd->path = f.file->f_path;
                        nd->inode = nd->path.dentry->d_inode;
                    }
                }

                // 循环追踪挂载点和链接直到路径的最后一层
                // while (!(error = link_path_walk(s, nd)) &&
                //     (s = open_last_lookups(nd, file, op)) != NULL)
                //     ;
                link_path_walk(s, nd);
                {
                    for(;;) {
                        // 到达路径的最后一层
                        if (unlikely(!*name)) {
                            /* stack已清空，整个path遍历完毕 */
                            if (!depth) {
                                nd->dir_uid = i_uid_into_mnt(mnt_userns, nd->inode);
                                nd->dir_mode = nd->inode->i_mode;
                                nd->flags &= ~LOOKUP_PARENT;
                                return 0;
                            }

                            // path=a/b, ln c/d a
                            // 路径中间出现链接，这种情况在到达最后一层d时需要继续查找
                            name = nd->stack[--depth].name;
                            link = walk_component(nd, 0);
                        } else {
                            /* not the last component */
                            link = walk_component(nd, WALK_MORE);
                            {
                                // 先看指定文件是否打开过
                                struct dentry *dentry = lookup_fast(nd, &inode, &seq);
                                if (unlikely(!dentry)) {
                                    // 创建并初始化dentry
                                    dentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);
                                    {
                                        dentry = d_alloc_parallel(dir, name, &wq);
                                        struct inode *inode = dir->d_inode;
                                        inode->i_op->lookup(inode, dentry, flags);
                                    }
                                }
                                // 继续遍历
                                step_into(nd, flags, dentry, inode, seq);
                                {
                                    struct path path;
                                    // 跟踪挂载点
                                    handle_mounts(nd, dentry, &path, &inode, &seq);
                                    {
                                        path->mnt = nd->path.mnt;
                                        path->dentry = dentry;
                                        traverse_mounts(path, &jumped, &nd->total_link_count, nd->flags);
                                        {
                                            // 从注册表查找挂载点记录
                                            struct vfsmount *mounted = lookup_mnt(path);
                                            // 路径切换到挂载点文件系统的root
                                            path->mnt = mounted;
                                            path->dentry = dget(mounted->mnt_root);
                                        }
                                        *inode = d_backing_inode(path->dentry);
                                    }
                                    // 非链接
                                    if (likely(!d_is_symlink(path.dentry))) {
                                        nd->path = path;
                                        nd->inode = inode;
                                        nd->seq = seq;
                                        return NULL;
                                    }
                                    // 跟踪链接
                                    return pick_link(nd, &path, inode, seq, flags);
                                    {
                                        // 读取链接路径
                                        const char *res = READ_ONCE(inode->i_link);
                                        if (!res) {
                                            // 查找链接
                                            inode->i_op->get_link(link->dentry, inode, &last->done);
                                        }
                                        if (*res == '/') {
                                            nd_jump_root(nd);
                                        }
                                        return res;
                                    }
                                }
                            }
                        }
                        if (unlikely(link)) {
                            // 当前路径剩余部分入栈，开始跟踪链接的路径
                            nd->stack[depth++].name = name;
                            name = link;
                            continue;
                        }
                    }
                }
                
                // 处理最后一层：不存在时可能会创建
                open_last_lookups(nd, file, op);
                {
                    struct dentry *dentry = lookup_open(nd, file, op, got_write);
                    {
                        struct dentry *dentry = d_alloc_parallel(dir, &nd->last, &wq);
                        if (dir_inode->i_op->atomic_open) {
                            dentry = atomic_open(nd, dentry, file, open_flag, mode);
                            return dentry;
                        }
                        // 查找
                        if (d_in_lookup(dentry)) {
                            dentry = dir_inode->i_op->lookup(dir_inode, dentry, nd->flags);
                        }
                        // 不存在则创建
                        if (!dentry->d_inode && (open_flag & O_CREAT)) {
                            dir_inode->i_op->create(mnt_userns, dir_inode, dentry, mode, open_flag & O_EXCL);
                        }
                    }
                    // 最后一层路径也许是个链接
                    step_into(nd, WALK_TRAILING, dentry, inode, seq);
                }

                do_open(nd, file, op);
                {
                    vfs_open(&nd->path, file);
                    {
                        file->f_path = *path;
                        return do_dentry_open(file, d_backing_inode(path->dentry), NULL);
                        {
                            file->f_inode = inode;
                            file->f_mapping = inode->i_mapping;
                            file->f_op = fops_get(inode->i_fop);
                            file->f_op->open(inode, f);
                        }
                    }
                }
            }

            restore_nameidata();
        }

        // 保存到fdt中
        fd_install(fd, f);
        {
            struct files_struct *files = current->files;
            struct fdtable *fdt = files_fdtable(files);
            rcu_assign_pointer(fdt->fd[fd], file);
        }
    }
}
```

### read

```c
ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
    struct fd f = fdget_pos(fd);
    // 当前位置
    loff_t *ppos = file_ppos(f.file);
    vfs_read(f.file, buf, count, ppos);
    {
        if (file->f_op->read)
            ret = file->f_op->read(file, buf, count, pos);
        else if (file->f_op->read_iter)
            ret = new_sync_read(file, buf, count, pos);
    }
}
```

### write

```c
ssize_t ksys_write(unsigned int fd, const char __user *buf, size_t count)
{
    struct fd f = fdget_pos(fd);
    loff_t *ppos = file_ppos(f.file);
    vfs_write(f.file, buf, count, ppos);
    {
        if (file->f_op->write)
            ret = file->f_op->write(file, buf, count, pos);
        else if (file->f_op->write_iter)
            ret = new_sync_write(file, buf, count, pos);
    }
}
```

## ramfs

`ramfs`是一个简单的基于内存的文件系统，以此为例说明文件系统各个组件的关联关系

### 注册文件系统

```c

static struct file_system_type ramfs_fs_type = {
    .name        = "ramfs",
    .init_fs_context = ramfs_init_fs_context,
    .parameters    = ramfs_fs_parameters,
    .kill_sb    = ramfs_kill_sb,
    .fs_flags    = FS_USERNS_MOUNT,
};

static int __init init_ramfs_fs(void)
{
    return register_filesystem(&ramfs_fs_type);
}
fs_initcall(init_ramfs_fs);

```

### mount

```c

static const struct fs_context_operations ramfs_context_ops = {
    .free        = ramfs_free_fc,
    .parse_param    = ramfs_parse_param,
    .get_tree    = ramfs_get_tree,
};

// 初始化fc
int ramfs_init_fs_context(struct fs_context *fc)
{
    fc->ops = &ramfs_context_ops;
}

// 填充super_block
static int ramfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct inode *inode;

    sb->s_maxbytes        = MAX_LFS_FILESIZE;
    sb->s_blocksize        = PAGE_SIZE;
    sb->s_blocksize_bits    = PAGE_SHIFT;
    sb->s_magic        = RAMFS_MAGIC;
    sb->s_op        = &ramfs_ops;
    sb->s_time_gran        = 1;

    // 生成root inode
    inode = ramfs_get_inode(sb, NULL, S_IFDIR, 0);
    {
        struct inode * inode = new_inode(sb);
        {
            const struct super_operations *ops = sb->s_op;
            if (ops->alloc_inode)
                inode = ops->alloc_inode(sb);
            else
                inode = kmem_cache_alloc(inode_cachep, GFP_KERNEL);
        }

        inode->i_ino = get_next_ino();
        inode->i_mapping->a_ops = &ram_aops;
        inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);

        switch (mode & S_IFMT) {
        default:
            // char设备/块设备等特殊文件
            init_special_inode(inode, mode, dev);
            break;
        case S_IFREG:
            // 普通文件
            inode->i_op = &ramfs_file_inode_operations;
            inode->i_fop = &ramfs_file_operations;
            break;
        case S_IFDIR:
            // 目录文件
            inode->i_op = &ramfs_dir_inode_operations;
            inode->i_fop = &simple_dir_operations;
            inc_nlink(inode);
            break;
        case S_IFLNK:
            // 链接
            inode->i_op = &page_symlink_inode_operations;
            break;
        }
    }
    sb->s_root = d_make_root(inode);
}

// 初始化super_block
static int ramfs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, ramfs_fill_super);
    {
        return vfs_get_super(fc, vfs_get_independent_super, fill_super);
        {
            struct super_block *sb = sget_fc(fc, test, set_anon_super_fc);
            {
                struct super_block *s = alloc_super(fc->fs_type, fc->sb_flags, user_ns);
                set_anon_super_fc(s, fc);
                {
                    // 查找空闲的设备号
                    int dev = ida_alloc_range(&unnamed_dev_ida, 1, (1 << MINORBITS) - 1, GFP_ATOMIC);
                    s->s_dev = MKDEV(0, dev);
                }
                return s;
            }

            if (!sb->s_root) {
                fill_super(sb, fc);
                sb->s_flags |= SB_ACTIVE;
                fc->root = dget(sb->s_root);
            } else {
                fc->root = dget(sb->s_root);
            }
        }
    }
}

```

### dir inode ops

```c
static const struct inode_operations ramfs_dir_inode_operations = {
    .create        = ramfs_create,     // 创建文件
    .lookup        = simple_lookup,    // 查找文件
    .link        = simple_link,      // 创建链接
    .unlink        = simple_unlink,    // 取消链接
    .symlink    = ramfs_symlink,    // 创建软链接
    .mkdir        = ramfs_mkdir,      // 创建目录
    .rmdir        = simple_rmdir,     // 删除目录
    .mknod        = ramfs_mknod,      // 创建inode
    .rename        = simple_rename,    // 重命名
    .tmpfile    = ramfs_tmpfile,    // 创建临时文件
};
```

`create`和`mkdir`都是直接调用`mknode`，只是`model`不同

```c
static int
ramfs_mknod(struct user_namespace *mnt_userns, struct inode *dir,
        struct dentry *dentry, umode_t mode, dev_t dev)
{
    struct inode * inode = ramfs_get_inode(dir->i_sb, dir, mode, dev);
    int error = -ENOSPC;

    if (inode) {
        d_instantiate(dentry, inode);
        dget(dentry);    /* Extra count - pin the dentry in core */
        error = 0;
        dir->i_mtime = dir->i_ctime = current_time(dir);
    }
    return error;
}
```

```c
struct dentry *simple_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
    if (dentry->d_name.len > NAME_MAX)
        return ERR_PTR(-ENAMETOOLONG);
    if (!dentry->d_sb->s_d_op)
        d_set_d_op(dentry, &simple_dentry_operations);
    d_add(dentry, NULL);
    return NULL;
}
```

`lookup`的实现第一次看可能会比较懵，本来是应该实现文件查找功能的，看起来啥也没干。
由于`ramfs`是基于内存的，是在内存中从0开始创建的，创建的过程中dentry已经缓存。再看上面`open`的过程

```c
walk_component(nd, WALK_MORE);
{
    // 先看指定文件是否打开过，查找dentry缓存
    struct dentry *dentry = lookup_fast(nd, &inode, &seq);
    if (unlikely(!dentry)) {
        // 缓存不存在才创建并初始化dentry
        dentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);
        {
            dentry = d_alloc_parallel(dir, name, &wq);
            struct inode *inode = dir->d_inode;
            inode->i_op->lookup(inode, dentry, flags);
        }
    }
}
```

`ramfs`查找文件时如果走到`lookup_slow`，文件肯定是不存在的，所以`lookup`只是设置了`delete`函数删除当前查找的dentry。

### dir file ops

`ramfs`的dir不支持读操作，此处没什么有价值的代码。

```c
const struct file_operations simple_dir_operations = {
    .open        = dcache_dir_open,
    .release    = dcache_dir_close,
    .llseek        = dcache_dir_lseek,
    .read        = generic_read_dir,
    .iterate_shared    = dcache_readdir,
    .fsync        = noop_fsync,
};
```

### file inode ops

```c
const struct inode_operations ramfs_file_inode_operations = {
    .setattr    = simple_setattr,
    .getattr    = simple_getattr,
};
```

### file file ops

```c
const struct file_operations ramfs_file_operations = {
    .read_iter    = generic_file_read_iter,
    .write_iter    = generic_file_write_iter,
    .mmap        = generic_file_mmap,
    .fsync        = noop_fsync,
    .splice_read    = generic_file_splice_read,
    .splice_write    = iter_file_splice_write,
    .llseek        = generic_file_llseek,
    .get_unmapped_area    = ramfs_mmu_get_unmapped_area,
};
```

读文件

```c
ssize_t generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    ssize_t retval = 0;
    return filemap_read(iocb, iter, retval);
    {
        struct pagevec pvec;
        pagevec_init(&pvec);

        // 读数据到page cache
        filemap_get_pages(iocb, iter, &pvec);
        {
            struct file *filp = iocb->ki_filp;
            struct address_space *mapping = filp->f_mapping;
            // 起始位置所在page
            pgoff_t index = iocb->ki_pos >> PAGE_SHIFT;
            // 截止位置所在page
            pgoff_t last_index = DIV_ROUND_UP(iocb->ki_pos + iter->count, PAGE_SIZE);
            // 读取数据
            filemap_get_read_batch(mapping, index, last_index, pvec);
            {
                // ramfs相当于所有的文件内容都在page_cache中
                XA_STATE(xas, &mapping->i_pages, index);
                for (head = xas_load(&xas); head; head = xas_next(&xas)) {
                    pagevec_add(pvec, head);
                }
            }
        }

        // 复制数据到user提供的buf
        for (i = 0; i < pagevec_count(&pvec); i++) {
            struct page *page = pvec.pages[i];
            copy_page_to_iter(page, offset, bytes, iter);
        }
    }
}
```

写文件

```c

const struct address_space_operations ram_aops = {
    .readpage    = simple_readpage,
    .write_begin    = simple_write_begin,
    .write_end    = simple_write_end,
    .set_page_dirty    = __set_page_dirty_no_writeback,
};

ssize_t generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    __generic_file_write_iter(iocb, from);
    {
        generic_perform_write(file, from, iocb->ki_pos);
        {
            do {
                // 计算第一个page的offset
                offset = (pos & (PAGE_SIZE - 1));
                bytes = min_t(unsigned long, PAGE_SIZE - offset, iov_iter_count(i));

                a_ops->write_begin(file, mapping, pos, bytes, flags, &page, &fsdata);
                // 复制user提供的数据到page_cache
                copy_page_from_iter_atomic(page, offset, bytes, i);
                a_ops->write_end(file, mapping, pos, bytes, copied, page, fsdata);
            } while (iov_iter_count(i));
        }
    }
}

int simple_write_begin(struct file *file, struct address_space *mapping,
            loff_t pos, unsigned len, unsigned flags,
            struct page **pagep, void **fsdata)
{
    struct page *page;
    pgoff_t index;

    // 文件位置转page_cache索引
    index = pos >> PAGE_SHIFT;

    // 查找index对应的page，不存在则分配
    page = grab_cache_page_write_begin(mapping, index, flags);
    {
        page = mapping_get_entry(mapping, index);
        if (!page && (fgp_flags & FGP_CREAT)) {
            page = __page_cache_alloc(gfp_mask);
            add_to_page_cache_lru(page, mapping, index, gfp_mask);
        }
    }

    *pagep = page;

    return 0;
}

static int simple_write_end(struct file *file, struct address_space *mapping,
            loff_t pos, unsigned len, unsigned copied,
            struct page *page, void *fsdata)
{
    set_page_dirty(page);
}

```