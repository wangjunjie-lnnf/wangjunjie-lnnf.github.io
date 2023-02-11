---
layout: post
title:  "mysql之innodb"
date:   2023-02-11 10:22:07 +0000
categories: jekyll
tags: mysql innodb
---

# innodb

## innodb初始化

```c++

int mysqld_main(int argc, char **argv)
{
    init_server_components();
    {
        dd::init(dd::enum_dd_init_type::DD_RESTART_OR_UPGRADE);
        {
            result = ::bootstrap::run_bootstrap_thread(..., &upgrade_57::do_pre_checks_and_initialize_dd, SYSTEM_THREAD_DD_INITIALIZE);
            {
                mysql_thread_create(key_thread_bootstrap, &thread_handle, &thr_attr, handle_bootstrap, &args);
                {
                    do_pre_checks_and_initialize_dd(THD *thd);
                    {
                        bootstrap::DDSE_dict_init(thd, DICT_INIT_CHECK_FILES, d->get_target_dd_version());
                        {
                            // innobase_hton->ddse_dict_init = innobase_ddse_dict_init;
                            handlerton *ddse = ha_resolve_by_legacy_type(thd, DB_TYPE_INNODB);
                            ddse->ddse_dict_init(dict_init_mode, version, &ddse_tables, &ddse_tablespaces);
                            {
                                innobase_init_files(dict_init_mode, tablespaces);
                                {
                                    srv_start(false);
                                    {
                                        // 创建buffer pool
                                        buf_pool_init(srv_buf_pool_size, srv_buf_pool_instances);
                                        {
                                            // 创建Adaptive Hash Index
                                            btr_search_sys_create(buf_pool_get_curr_size() / sizeof(void *) / 64);
                                        }

                                        // double write buffer初始化
                                        dblwr::open();

                                        log_sys_init(create_new_db, flushed_lsn, new_files_lsn);
                                        {
                                            log_sys_create()
                                            {
                                                // 创建redo log buffer
                                                log_allocate_buffer(log);
                                                log_allocate_write_ahead_buffer(log);
                                            }
                                        }

                                        dict_boot();
                                        {
                                            // 创建change buffer
                                            ibuf_init_at_db_start();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


```


## 数据结构

`innodb`架构
![innodb-arch](/assets/images/2023-02-11/mysql-arch.jpg)

## In-Memory结构

### Buffer Pool

The buffer pool is an area in main memory where InnoDB caches table and index data as it is accessed. The buffer pool permits frequently used data to be accessed directly from memory, which speeds up processing. On dedicated servers, up to 80% of physical memory is often assigned to the buffer pool.

For efficiency of high-volume read operations, the buffer pool is divided into pages that can potentially hold multiple rows. For efficiency of cache management, the buffer pool is implemented as a linked list of pages; data that is rarely used is aged out of the cache using a variation of the least recently used (LRU) algorithm.

`Buffer Pool`大小和个数由物理内存和配置决定

```c++

const ulint srv_buf_pool_min_size = 5 * 1024 * 1024;

static void innodb_buffer_pool_size_init() {
    // innodb_dedicated_server表示此结点为数据库专用
    if (srv_dedicated_server && sysvar_source_svc != nullptr) {
        if (source == COMPILED) {
            double server_mem = get_sys_mem();

            if (server_mem < 1.0) {
            ;
            } else if (server_mem <= 4.0) {
                // 1G<=内存<=4G内存时50%用于buf_pool
                srv_buf_pool_size = static_cast<ulint>(server_mem * 0.5 * GB);
            } else {
                // 内存>4G内存时75%用于buf_pool
                srv_buf_pool_size = static_cast<ulint>(server_mem * 0.75 * GB);
            }
        }
    }

    if (srv_buf_pool_size >= 1G) {
        // 1G以上默认8个实例
        if (srv_buf_pool_instances == srv_buf_pool_instances_default) {
            srv_buf_pool_instances = 8;
        }
    } else {
        srv_buf_pool_instances = 1;
    }
}

```

`Buffer Pool`初始化

```c++

buf_pool_t *buf_pool_ptr;

dberr_t buf_pool_init(ulint total_size, ulint n_instances) {

    // 创建buf_pool注册表
    buf_pool_ptr = (buf_pool_t *)ut::zalloc_withkey(n_instances * sizeof *buf_pool_ptr);

    for (i = 0; i < n_instances; /* no op */) {
        // 多个线程并行创建buf_pool
        threads.emplace_back(std::thread(buf_pool_create, &buf_pool_ptr[id], size, id, ...));
    }

    // old占3/8
    buf_LRU_old_ratio_update(100 * 3 / 8, false);

    /* 创建Adaptive Hash Index: 每64个指针分配一个slot */
    btr_search_sys_create(buf_pool_get_curr_size() / sizeof(void *) / 64);
    {
        // 默认8个分区
        ulong btr_ahi_parts = 8;

        // 每个分区创建一个读写锁
        for (ulint i = 0; i < btr_ahi_parts; ++i) {
            btr_search_latches[i] = reinterpret_cast<rw_lock_t *>(malloc(..., sizeof(rw_lock_t)));
            rw_lock_create(btr_search_latch_key, btr_search_latches[i], SYNC_SEARCH_SYS);
        }

        // 每个分区创建一个hash_table
        btr_search_sys->hash_tables = reinterpret_cast<hash_table_t **>(malloc(..., sizeof(hash_table_t *) * btr_ahi_parts));
        for (ulint i = 0; i < btr_ahi_parts; ++i) {
            // 每个hash_table对应一个分区
            btr_search_sys->hash_tables[i] = ib_create((hash_size / btr_ahi_parts), ...);
            btr_search_sys->hash_tables[i]->adaptive = true;
        }
    }
}

void buf_pool_create(buf_pool_t *buf_pool, ulint buf_pool_size, ulint instance_no, ...)
{
    buf_pool->n_chunks = buf_pool_size / srv_buf_pool_chunk_unit;
    buf_pool->chunks = reinterpret_cast<buf_chunk_t *>(zalloc(..., buf_pool->n_chunks * sizeof(*chunk)));

    UT_LIST_INIT(buf_pool->LRU);
    UT_LIST_INIT(buf_pool->free);
    UT_LIST_INIT(buf_pool->withdraw);
    UT_LIST_INIT(buf_pool->flush_list);
    UT_LIST_INIT(buf_pool->unzip_LRU);
    UT_LIST_INIT(buf_pool->zip_clean);

    for (i = 0; i < UT_ARR_SIZE(buf_pool->zip_free); ++i) {
      UT_LIST_INIT(buf_pool->zip_free[i]);
    }

    do {
        buf_chunk_init(buf_pool, chunk, chunk_size, mutex);
        {
            // 按page向下取整
            mem_size = ut_2pow_round(mem_size, UNIV_PAGE_SIZE);
            // 每个block管理一个page，分配n个page的block
            mem_size += ut_2pow_round((mem_size / UNIV_PAGE_SIZE) * (sizeof *block) + (UNIV_PAGE_SIZE - 1), UNIV_PAGE_SIZE);
            buf_pool->allocate_chunk(mem_size, chunk);
            {
                chunk->mem = static_cast<uint8_t *>(ut::malloc_large_page_withkey(..., mem_size, ...));
            }
            // 开头的n个page存储block
            chunk->blocks = (buf_block_t *)chunk->mem;

            block = chunk->blocks;
            
            // 初始化每个block
            for (i = chunk->size; i--;) {
                buf_block_init(buf_pool, block, frame);
                {
                    // frame指向block对应的数据块
                    block->frame = frame;
                    block->page.buf_pool_index = buf_pool_index(buf_pool);
                    block->page.state = BUF_BLOCK_NOT_USED;
                }

                block++;
                frame += UNIV_PAGE_SIZE;
            }
        }
        // chunk->size表示chunk中存储数据的page的个数
        buf_pool->curr_size += chunk->size;
    } while (++chunk < buf_pool->chunks + buf_pool->n_chunks);

    buf_pool->page_hash = ib_create(2 * buf_pool->curr_size, ...);
    buf_pool->zip_hash = ut::new_<hash_table_t>(2 * buf_pool->curr_size);
}

```

![buf_pool](/assets/images/2023-02-11/buf_pool.png)

---

`Buffer Pool LRU Algorithm`

![buf_pool-lru](/assets/images/2023-02-11/buf_pool-lru.png)

The buffer pool is managed as a list using a variation of the LRU algorithm. When room is needed to add a new page to the buffer pool, the least recently used page is evicted and a new page is added to the middle of the list. This midpoint insertion strategy treats the list as two sublists:
* At the head, a sublist of new (“young”) pages that were accessed recently
* At the tail, a sublist of old pages that were accessed less recently  

The algorithm keeps frequently used pages in the new sublist. The old sublist contains less frequently used pages; these pages are candidates for eviction.

By default, the algorithm operates as follows:

* 3/8 of the buffer pool is devoted to the old sublist.
* The midpoint of the list is the boundary where the tail of the new sublist meets the head of the old sublist.
* When InnoDB reads a page into the buffer pool, it initially inserts it at the midpoint (the head of the old sublist). A page can be read because it is required for a user-initiated operation such as an SQL query, or as part of a read-ahead operation performed automatically by InnoDB.
* Accessing a page in the old sublist makes it “young”, moving it to the head of the new sublist. If the page was read because it was required by a user-initiated operation, the first access occurs immediately and the page is made young. If the page was read due to a read-ahead operation, the first access does not occur immediately and might not occur at all before the page is evicted.
* As the database operates, pages in the buffer pool that are not accessed “age” by moving toward the tail of the list. Pages in both the new and old sublists age as other pages are made new. Pages in the old sublist also age as pages are inserted at the midpoint. Eventually, a page that remains unused reaches the tail of the old sublist and is evicted.  

By default, pages read by queries are immediately moved into the new sublist, meaning they stay in the buffer pool longer. A table scan, performed for a mysqldump operation or a SELECT statement with no WHERE clause, for example, can bring a large amount of data into the buffer pool and evict an equivalent amount of older data, even if the new data is never used again. Similarly, pages that are loaded by the read-ahead background thread and accessed only once are moved to the head of the new list. These situations can push frequently used pages to the old sublist where they become subject to eviction.

---

### Change Buffer

The change buffer is a special data structure that caches changes to `secondary index` pages when those pages are not in the `buffer pool`. The buffered changes, which may result from `INSERT`, `UPDATE`, or `DELETE` operations (DML), are merged later when the pages are loaded into the buffer pool by other read operations.

`Change Buffer`用于缓存二级索引未加载到`buffer pool`的page的变更。

Unlike clustered indexes, secondary indexes are usually nonunique, and inserts into secondary indexes happen in a relatively random order. Similarly, deletes and updates may affect secondary index pages that are not adjacently located in an index tree. Merging cached changes at a later time, when affected pages are read into the buffer pool by other operations, avoids substantial random access I/O that would be required to read secondary index pages into the buffer pool from disk.

Periodically, the purge operation that runs when the system is mostly idle, or during a slow shutdown, writes the updated index pages to disk. The purge operation can write disk blocks for a series of index values more efficiently than if each value were written to disk immediately.

Change buffer merging may take several hours when there are many affected rows and numerous secondary indexes to update. During this time, disk I/O is increased, which can cause a significant slowdown for disk-bound queries. Change buffer merging may also continue to occur after a transaction is committed, and even after a server shutdown and restart.

In memory, the change buffer occupies part of the buffer pool. On disk, the change buffer is part of the system tablespace, where index changes are buffered when the database server is shut down.


The type of data cached in the change buffer is governed by the `innodb_change_buffering` variable. You can enable or disable buffering for inserts, delete operations (when index records are initially marked for deletion) and purge operations (when index records are physically deleted). An update operation is a combination of an insert and a delete. The default innodb_change_buffering value is all.

Permitted innodb_change_buffering values include:
* all  
The default value: buffer inserts, delete-marking operations, and purges.
* none  
Do not buffer any operations.
* inserts  
Buffer insert operations.
* deletes  
Buffer delete-marking operations.
* changes  
Buffer both inserts and delete-marking operations.
* purges  
Buffer the physical deletion operations that happen in the background.

Change buffering is not supported for a secondary index if the index contains a descending index column or if the primary key includes a descending index column.

![change-buffer](/assets/images/2023-02-11/change-buffer.png)

`Change Buffer`初始化
```c++

void ibuf_init_at_db_start(void) {

    ibuf_t *ibuf = static_cast<ibuf_t *>(zalloc(..., sizeof(ibuf_t)));
    // 最大占用1/4
    ibuf->max_size = ((buf_pool_get_curr_size() / UNIV_PAGE_SIZE) * 25) / 100;

    block = buf_page_get(page_id_t(IBUF_SPACE_ID, FSP_IBUF_TREE_ROOT_PAGE_NO), ...);
    root = buf_block_get_frame(block);

    // 创建内存表innodb_change_buffer
    ibuf->index = dict_mem_index_create("innodb_change_buffer", ...);
    ibuf->index->table = dict_mem_table_create("innodb_change_buffer", IBUF_SPACE_ID, 1, 0, 0, 0, 0);
}

```

### Adaptive Hash Index

The adaptive hash index enables InnoDB to perform more like an in-memory database on systems with appropriate combinations of workload and sufficient memory for the buffer pool without sacrificing transactional features or reliability. 

Based on the observed pattern of searches, a hash index is built using a prefix of the index key. The prefix can be any length, and it may be that only some values in the B-tree appear in the hash index. Hash indexes are built on demand for the pages of the index that are accessed often.

If a table fits almost entirely in main memory, a hash index speeds up queries by enabling direct lookup of any element, turning the index value into a sort of pointer. InnoDB has a mechanism that monitors index searches. If InnoDB notices that queries could benefit from building a hash index, it does so automatically.

```c++

// Number of adaptive hash index partition
ulong btr_ahi_parts = 8;

void btr_search_sys_create(ulint hash_size) {

    /* Step-1: Allocate latches (1 per part). */
    btr_search_latches = reinterpret_cast<rw_lock_t **>(malloc(..., sizeof(rw_lock_t *) * btr_ahi_parts));
    for (ulint i = 0; i < btr_ahi_parts; ++i) {
        btr_search_latches[i] = reinterpret_cast<rw_lock_t *>(malloc(..., sizeof(rw_lock_t)));
        rw_lock_create(..., btr_search_latches[i], SYNC_SEARCH_SYS);
    }

    /* Step-2: Allocate hash tables. */
    btr_search_sys = reinterpret_cast<btr_search_sys_t *>(malloc(..., sizeof(btr_search_sys_t)));
    btr_search_sys->hash_tables = reinterpret_cast<hash_table_t **>(malloc(..., sizeof(hash_table_t *) * btr_ahi_parts));
    for (ulint i = 0; i < btr_ahi_parts; ++i) {
        btr_search_sys->hash_tables[i] = ib_create((hash_size / btr_ahi_parts), ...);
    }
}

```

### Log Buffer

The log buffer is the memory area that holds data to be written to the log files on disk. Log buffer size is defined by the `innodb_log_buffer_size` variable. The default size is 16MB. The contents of the log buffer are periodically flushed to disk. A large log buffer enables large transactions to run without the need to write redo log data to disk before the transactions commit. Thus, if you have transactions that update, insert, or delete many rows, increasing the size of the log buffer saves disk I/O.

```c++

static void log_allocate_buffer(log_t &log) {
    // 没有结构
    log.buf.alloc(..., ut::Count{srv_log_buffer_size});
}

```

记录`redo log`

```c++

mtr_t mtr;

mtr_start(&mtr);
{
    // 从heap上分配内存
    new (&m_impl.m_log) mtr_buf_t();
    m_impl.m_log_mode = MTR_LOG_ALL;
    m_impl.m_state = MTR_STATE_ACTIVE;
}

// 需要记录log的任意操作: 每条log都带类型
mlog_write_ulint(..., MLOG_2BYTES, mtr);
{
    // 返回待写入数据的内存地址，必要时扩展内存
    byte *log_ptr = nullptr;
    mlog_open(mtr, REDO_LOG_INITIAL_INFO_SIZE + 2 + 5, log_ptr);
    {
        block_t *block = has_space(size) ? back() : add_block();
    }

    // 写入数据: 类型(1B) + 压缩的space_id(5B) + 压缩的page_id(5B) + page_offset(2B) + value
    log_ptr = mlog_write_initial_log_record_fast(ptr, type, log_ptr, mtr);
    {
        mach_write_to_1(log_ptr, type);
        log_ptr++;

        log_ptr += mach_write_compressed(log_ptr, space_id);
        log_ptr += mach_write_compressed(log_ptr, page_no);
        
        // 累加log条数
        mtr->added_rec();
    }

    mach_write_to_2(log_ptr, page_offset(ptr));
    log_ptr += 2;

    log_ptr += mach_write_compressed(log_ptr, val);

    // 计算log长度
    mlog_close(mtr, log_ptr);
    {
        block->close(ptr);
    }
}

mtr_commit(&mtr);
{
    Command cmd(this);
    cmd.execute();
    {
        // 在log.buf上预留内存
        auto handle = log_buffer_reserve(*log_sys, len);

        write_log.m_handle = handle;
        write_log.m_lsn = handle.start_lsn;

        m_impl->m_log.for_each_block(write_log);
        {
            // copy数据到log.buf
            end_lsn = log_buffer_write(*log_sys, block->begin(), block->used(), start_lsn);
        }
    }
}

```


## On-Disk数据结构

### Tablespace

表空间是一个逻辑结构，表空间下可以有多个物理文件(`.ibd`)用于存储数据。`.ibd`文件头里记录着表空间id，系统启动时会扫描data目录下的所有数据文件，重构表空间和数据文件的对应关系。

Each tablespace consists of database pages. Every tablespace in a MySQL instance has the same page size. By default, all tablespaces have a page size of 16KB.

每个表空间的page大小一致，默认16KB。

The pages are grouped into extents of size 1MB for pages up to 16KB in size (64 consecutive 16KB pages, or 128 8KB pages, or 256 4KB pages). For a page size of 32KB, extent size is 2MB. For page size of 64KB, extent size is 4MB. The “files” inside a tablespace are called segments in InnoDB.

`page`组织成`extent`。每个`.ibd`文件可以包含多个`segment`。

When a segment grows inside the tablespace, InnoDB allocates the first 32 pages to it one at a time. After that, InnoDB starts to allocate whole extents to the segment. InnoDB can add up to 4 extents at a time to a large segment to ensure good sequentiality of data.

Two segments are allocated for each index in InnoDB. One is for nonleaf nodes of the B-tree, the other is for the leaf nodes. Keeping the leaf nodes contiguous on disk enables better sequential I/O operations, because these leaf nodes contain the actual table data.

每个索引分配两个segment，分别存储非叶子结点和叶子结点。

Some pages in the tablespace contain bitmaps of other pages, and therefore a few extents in an InnoDB tablespace cannot be allocated to segments as a whole, but only as individual pages.

When you ask for available free space in the tablespace by issuing a `SHOW TABLE STATUS` statement, InnoDB reports the extents that are definitely free in the tablespace. InnoDB always reserves some extents for cleanup and other internal purposes; these reserved extents are not included in the free space.

When you delete data from a table, InnoDB contracts the corresponding B-tree indexes. Whether the freed space becomes available for other users depends on whether the pattern of deletes frees individual pages or extents to the tablespace. Dropping a table or deleting all rows from it is guaranteed to release the space to other users, but remember that deleted rows are physically removed only by the purge operation, which happens automatically some time after they are no longer needed for transaction rollbacks or consistent reads.

删除数据不一定能释放磁盘空间。

`innodb`磁盘文件对应关系
![mysql-disk](/assets/images/2023-02-11/mysql-disk.jpg)

`redo log`在`8.0.30`之前的文件名格式是`ib_logfilex`，现在命名格式是`#ib_redox`

---

* System Tablespace

The system tablespace is the storage area for the `change buffer`. It may also contain table and index data if tables are created in the system tablespace rather than `file-per-table` or `general tablespaces`.

系统表空间包含change buffer，创建表时也可以指定把数据存储在系统表空间。

* File-Per-Table Tablespace

A file-per-table tablespace contains data and indexes for a single InnoDB table, and is stored on the file system in a single data file.

`innodb_file_per_table`参数默认开启，每个表默认使用各自独立的表空间

* General Tablespaces

A `general tablespace` is a shared InnoDB tablespace that is created using `CREATE TABLESPACE` syntax

通用表空间由用户创建，可以存储多个表的数据。

* Undo Tablespaces

`Undo tablespaces` contain undo logs, which are collections of records containing information about how to undo the latest change by a transaction to a `clustered index` record.

Undo表空间存储undo log，在事务回滚时恢复聚集索引的数据。

* Temporary Tablespaces

InnoDB uses `session temporary tablespaces` and a `global temporary tablespace`.

`Session temporary tablespaces` store user-created temporary tables and internal temporary tables created by the optimizer when InnoDB is configured as the storage engine for on-disk internal temporary tables.

The `global temporary tablespace` (`ibtmp1`) stores rollback segments for changes made to user- created temporary tables.

### Doublewrite Buffer

The `doublewrite buffer` is a storage area where InnoDB writes pages flushed from the `buffer pool` before writing the pages to their proper positions in the InnoDB data files. If there is an operating system, storage subsystem, or unexpected mysqld process exit in the middle of a page write, InnoDB can find a good copy of the page from the doublewrite buffer during crash recovery.

mysql的page默认16KB，磁盘的page一般是4KB，mysql的一个page要分4次才能写入磁盘，如果中间断开会导致数据不一致。

Prior to MySQL 8.0.20, the `doublewrite buffer` storage area is located in the InnoDB `system tablespace`. As of MySQL 8.0.20, the `doublewrite buffer` storage area is located in doublewrite files.

The `innodb_doublewrite_files` variable defines the number of doublewrite files. By default, two doublewrite files are created for each `buffer pool` instance: A flush list doublewrite file and an LRU list doublewrite file.

The flush list doublewrite file is for pages flushed from the buffer pool flush list. The default size of a flush list doublewrite file is the `InnoDB page size` * `doublewrite pages` bytes.

The LRU list doublewrite file is for pages flushed from the buffer pool LRU list. It also contains slots for single page flushes. The default size of an LRU list doublewrite file is the `InnoDB page size` * (`doublewrite pages` + (512 / `the number of buffer pool instances`)) where 512 is the total number of slots reserved for single page flushes.

At a minimum, there are two doublewrite files. The maximum number of doublewrite files is two times the number of buffer pool instances.

Doublewrite file names have the following format: `#ib_page_size_file_number.dblwr`.

### Redo Log

Redo log files reside in the `#innodb_redo directory` in the data directory unless a different directory was specified by the `innodb_log_group_home_dir` variable. If innodb_log_group_home_dir was defined, the redo log files reside in the #innodb_redo directory in that directory. There are two types of redo log files, `ordinary` and `spare`. Ordinary redo log files are those being used. Spare redo log files are those waiting to be used. InnoDB tries to maintain 32 redo log files in total, with each file equal in size to `1/32` * `innodb_redo_log_capacity`.

Redo log files use an `#ib_redoN` naming convention, where N is the redo log file number. Spare redo log files are denoted by a `_tmp` suffix. 

Each ordinary redo log file is associated with a particular range of LSN values. `SELECT FILE_NAME, START_LSN, END_LSN FROM performance_schema.innodb_redo_log_files`可以查询每个redo log的LSN。

When doing a checkpoint, InnoDB stores the checkpoint LSN in the header of the file which contains this LSN. During recovery, all redo log files are checked and recovery starts at the latest checkpoint LSN.

```c++

// redo log文件头
struct Log_file_header {
  /** Format of the log file. */
  uint32_t m_format;

  /** LSN of the first log block (%512 == 0). */
  lsn_t m_start_lsn;

  std::string m_creator_name;
  Log_flags m_log_flags;
  Log_uuid m_log_uuid;
};

// 每条redo log都有类型
// 类型(1B) + 压缩的space_id(5B) + 压缩的page_id(5B) + page_offset(2B) + value
enum mlog_id_t {
    ...
}

```

### Undo Log

An undo log is a collection of undo log records associated with a single read-write transaction. An undo log record contains information about how to undo the latest change by a transaction to a `clustered index` record. If another transaction needs to see the original data as part of a consistent read operation, the unmodified data is retrieved from undo log records. Undo logs exist within `undo log segments`, which are contained within `rollback segments`. Rollback segments reside in `undo tablespaces` and in the `global temporary tablespace`.

Undo logs that reside in the `global temporary tablespace` are used for transactions that modify data in user-defined temporary tables. These undo logs are not redo-logged, as they are not required for crash recovery. They are used only for rollback while the server is running. This type of undo log benefits performance by avoiding redo logging I/O.

Each `undo tablespace` and the `global temporary tablespace` individually support a maximum of 128 rollback segments. The `innodb_rollback_segments` variable defines the number of rollback segments.

The number of transactions that a rollback segment supports depends on the number of undo slots in the rollback segment and the number of undo logs required by each transaction. The number of undo slots in a rollback segment differs according to InnoDB page size.
`number-of-undo-slots = InnoDB-page-size / 16`

A transaction is assigned up to four undo logs, one for each of the following operation types: 
1. INSERT operations on user-defined tables
2. UPDATE and DELETE operations on user-defined tables
3. INSERT operations on user-defined temporary tables
4. UPDATE and DELETE operations on user-defined temporary tables

Given the factors described above, the following formulas can be used to estimate the number of concurrent read-write transactions that InnoDB is capable of supporting.

* If each transaction performs either an INSERT or an UPDATE or DELETE operation, the number of concurrent read-write transactions that InnoDB is capable of supporting is:
`(innodb_page_size / 16) * innodb_rollback_segments * number-of-undo-tablespaces`

* If each transaction performs an INSERT operation on a temporary table, the number of concurrent read-write transactions that InnoDB is capable of supporting is:
`(innodb_page_size / 16) * innodb_rollback_segments`

## 处理流程