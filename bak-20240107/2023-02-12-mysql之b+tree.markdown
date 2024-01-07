---
layout: post
title:  "mysql之b+tree"
date:   2023-02-12 10:22:07 +0000
categories: jekyll
tags: mysql b+tree
---

# b+tree

## 创建表空间

![page-0](/assets/images/2023-02-12/page-0.png)

默认`innodb_file_per_table=ON`，每个表使用独立的表空间

```c
struct HA_CREATE_INFO {
    const CHARSET_INFO *table_charset{nullptr};
    const CHARSET_INFO *default_table_charset{nullptr};
    bool schema_read_only{false};
    LEX_STRING connect_string{nullptr, 0};
    const char *password{nullptr};
    const char *tablespace{nullptr};
    LEX_STRING comment{nullptr, 0};

    // 压缩和加密算法
    LEX_STRING compress{nullptr, 0};
    LEX_STRING encrypt_type{nullptr, 0};

    const char *data_file_name{nullptr};
    const char *index_file_name{nullptr};
    const char *alias{nullptr};

    ulonglong max_rows{0};
    ulonglong min_rows{0};
    ulonglong auto_increment_value{0};
    ulong table_options{0};
    ulong avg_row_length{0};
    uint64_t used_fields{0};

    // Can only be 1,2,4,8 or 16
    std::uint32_t key_block_size{0};
    // 存储引擎
    handlerton *db_type{nullptr};

    // 行格式
    enum row_type row_type = ROW_TYPE_DEFAULT;
    // 基于磁盘或基于内存
    ha_storage_media storage_media{HA_SM_DEFAULT}; 
}

dberr_t row_create_table_for_mysql(dict_table_t *&table,
                                   const char *compression,
                                   const HA_CREATE_INFO *create_info,
                                   trx_t *trx, mem_heap_t *heap) {
    // 创建表空间
    dict_build_table_def(table, create_info, trx);
    {
        dict_build_tablespace_for_table(table, create_info, trx);
        {
            needs_file_per_table = DICT_TF2_FLAG_IS_SET(table, DICT_TF2_USE_FILE_PER_TABLE);
            if (needs_file_per_table) {
                // 创建表空间: 默认分配7个page
                // - page 0 is the fsp header and an extent descriptor page,
                // - page 1 is an ibuf bitmap page,
                // - page 2 is the first inode page,
                // - page 3 will contain the root of the clustered index
                fil_ibd_create(space, tablespace_name.c_str(), filepath, fsp_flags, size);
                {
                    os_file_create(..., OS_FILE_CREATE, OS_FILE_NORMAL, OS_DATA_FILE);
                    {
                        // 禁用os的page-cache
                        if (type == OS_DATA_FILE || type == OS_DBLWR_FILE) {
                            os_file_set_nocache(file.m_file, name, mode_str);
                            {
                                fcntl(fd, F_SETFL, O_DIRECT);
                            }
                        }
                    }

                    fil_write_initial_pages(file, path, type, size, nullptr, space_id, ...);
                    {
                        // fallocate: 申请7个page的空间
                        posix_fallocate(file.m_file, 0, sz);
                        // 使用fallocate清空page-0
                        os_is_sparse_file_supported(file);

                        // 写入page-0
                        auto page = ut::aligned_zalloc(2 * page_size.logical(), page_size.logical());
                        fsp_header_set_field(page, FSP_SPACE_ID, space_id);
                        fsp_header_set_field(page, FSP_SPACE_FLAGS, flags);
                        mach_write_to_4(page + FIL_PAGE_ARCH_LOG_NO_OR_SPACE_ID, space_id);
                        mach_write_to_4(page + FIL_PAGE_SRV_VERSION, ...);
                        mach_write_to_4(page + FIL_PAGE_SPACE_VERSION, ...);

                        // 计算checksum
                        buf_flush_init_for_writing(nullptr, page, nullptr, 0, ...);
                        os_file_write(request, path, file, page, 0, page_size.physical());
                    }

                    // 表空间的内存表示
                    fil_space_create(name, space_id, flags, type);
                }

                fsp_header_init(table->space, size, &mtr);
                {

                }

                // SDI = Serialized Dictionary Information
                // 冗余存储表空间和表元信息
                btr_sdi_create_index(table->space, false);
            }
        }
    }

    // 增加系统字段
    dict_table_add_system_columns(table, heap);
    {
        // 有主键的聚集索引不需要此列
        dict_mem_table_add_col(table, heap, "DB_ROW_ID", DATA_SYS,
                                DATA_ROW_ID | DATA_NOT_NULL, DATA_ROW_ID_LEN, false,
                                phy_pos, v_added, v_dropped);

        // DB_TRX_ID表示修改此记录的事务id
        dict_mem_table_add_col(table, heap, "DB_TRX_ID", DATA_SYS,
                                DATA_TRX_ID | DATA_NOT_NULL, DATA_TRX_ID_LEN, false,
                                phy_pos, v_added, v_dropped);

        if (!table->is_intrinsic()) {
            // 非内置表增加DB_ROLL_PTR字段，更新时指向undo表空间内的旧版本，构成版本链
            dict_mem_table_add_col(table, heap, "DB_ROLL_PTR", DATA_SYS,
                                DATA_ROLL_PTR | DATA_NOT_NULL, DATA_ROLL_PTR_LEN,
                                false, phy_pos, v_added, v_dropped);
        }
    }
}
```

## 插入

![page-data](/assets/images/2023-02-12/page-data.png)

```c
int ha_innobase::write_row(uchar *record)
{
    // 构造模板转换mysql格式到innodb格式
    build_template(true);

    row_insert_for_mysql((byte *)record, m_prebuilt);
    {
        row_get_prebuilt_insert_row(prebuilt);
        {
            // 表结构未变化
            if (prebuilt->ins_node != nullptr) {
                if (prebuilt->trx_id == table->def_trx_id &&
                    UT_LIST_GET_LEN(prebuilt->ins_node->entry_list) == UT_LIST_GET_LEN(table->indexes)) {
                    return (prebuilt->ins_node->row);
                }
            }
        }

        node = prebuilt->ins_node;

        // 插入记录
        thr->run_node = node;
        row_ins_step(thr);
        {
            trx = thr_get_trx(thr);
            node = thr->run_node;

            // 写入6字节的trx_id
            trx_write_trx_id(node->trx_id_buf, trx->id);

            // 加IX锁
            if (node->state == INS_NODE_SET_IX_LOCK) {
                node->state = INS_NODE_ALLOC_ROW_ID;
                lock_table(0, node->table, LOCK_IX, thr);
                node->trx_id = trx->id;
            }

            row_ins(node, thr);
            {
                if (node->state == INS_NODE_ALLOC_ROW_ID) {
                    // 生成row_id
                    row_ins_alloc_row_id_step(node);
                    {
                        if (dict_index_is_unique(node->table->first_index())) {
                            return;
                        }
                    }

                    // 聚集索引
                    node->index = node->table->first_index();
                    node->entry = UT_LIST_GET_FIRST(node->entry_list);

                    // 复制insert语句中的字段值
                    if (node->ins_type == INS_VALUES) {
                        row_ins_get_row_from_values(node);
                    }
                    
                    node->state = INS_NODE_INSERT_ENTRIES;
                }

                // 更新每个索引
                while (node->index != nullptr) {
                    row_ins_index_entry_step(node, thr);
                    {
                        // 设置字段值
                        row_ins_index_entry_set_vals(node->index, node->entry, node->row);
                        row_ins_index_entry(node->index, node->entry, node->ins_multi_val_pos, thr);
                        {
                            if (index->is_clustered()) {
                                return (row_ins_clust_index_entry(index, entry, thr, false));
                                {
                                    // 先尝试只修改叶子节点是否可行
                                    err = row_ins_clust_index_entry_low(flags, BTR_MODIFY_LEAF, index, n_uniq, entry, thr, ...);
                                    if (err == DB_FAIL) {
                                        // 修改整个tree
                                        row_ins_clust_index_entry_low(flags, BTR_MODIFY_TREE, index, n_uniq, entry, thr, ...);
                                    }
                                }
                            } else if (index->is_multi_value()) {
                                // 插入多列索引
                                return (row_ins_sec_index_multi_value_entry(index, entry, multi_val_pos, thr));
                            } else {
                                // 插入二级索引
                                return (row_ins_sec_index_entry(index, entry, thr, false));
                            }
                        }
                    }

                    node->index = node->index->next();
                    node->entry = UT_LIST_GET_NEXT(tuple_list, node->entry);
                }
            }
        }

        dict_table_n_rows_inc(table);
        row_update_statistics_if_needed(table);
    }
}

// 插入聚集索引
dberr_t row_ins_clust_index_entry_low(uint32_t flags, ulint mode,
                                      dict_index_t *index, ulint n_uniq,
                                      dtuple_t *entry, que_thr_t *thr,
                                      bool dup_chk_only) {
    // 先在叶子节点中定位到小于等于待插入记录的位置
    btr_pcur_t pcur;                                    
    pcur.open(index, 0, entry, PAGE_CUR_LE, mode, &mtr, ...);

    btr_cur_t *cursor = pcur.get_btr_cur();
    if (mode != BTR_MODIFY_TREE) {
        btr_cur_optimistic_insert(flags, cursor, &offsets, &offsets_heap,
                                  entry, &insert_rec, &big_rec, thr, &mtr);
        {
            // 超过空页可用存储的一半
            if (page_zip_rec_needs_ext(rec_size, ..., page_size)) {
                // 把最长的字段挪到页外存储,索引只存储20字节的引用
                big_rec_vec = dtuple_convert_big_rec(index, nullptr, entry);
                // 重新计算record size
                rec_size = rec_get_converted_size(index, entry);
            }

            // 可用空间不足
            if (max_size < rec_size) {
                goto fail;
            }

            // 如果有连续插入的趋势，需要保留部分空间
            if (leaf && ... && index->is_clustered() &&
                page_get_n_recs(page) >= 2 &&
                dict_index_get_space_reserve() + rec_size > max_size) {
                goto fail;
            }

            page_cursor = btr_cur_get_page_cur(cursor);
            rec_t *page_cursor_rec = page_cur_get_rec(page_cursor);

            btr_cur_ins_lock_and_undo(flags, cursor, entry, thr, mtr, &inherit);
            {
                // 加锁: gap锁和插入意向锁
                lock_rec_insert_check_and_lock(flags, rec, btr_cur_get_block(cursor), index, thr, mtr, ...);
                {
                    const rec_t *next_rec = page_rec_get_next_const(rec);
                    // heap_no标识锁位置
                    ulint heap_no = page_rec_get_heap_no(next_rec);

                    ulint type_mode = LOCK_X | LOCK_GAP | LOCK_INSERT_INTENTION;
                    auto conflicting = lock_rec_other_has_conflicting(type_mode, block, heap_no, trx);
                    if (conflicting.wait_for != nullptr) {
                        RecLock rec_lock(thr, index, block, heap_no, type_mode);
                        rec_lock.add_to_waitq(conflicting.wait_for);
                    }
                }

                // 记录undo log
                trx_undo_report_row_operation(flags, TRX_UNDO_INSERT_OP, thr, index, ..., &roll_ptr);
                {
                    // 从undo表空间分配page
                    page_no = undo->last_page_no;
                    undo_block = buf_page_get_gen(page_id_t(undo->space, page_no), undo->page_size, ..., &mtr);

                    offset = trx_undo_page_report_insert(undo_page, trx, index, clust_entry, &mtr);
                    {
                        first_free = mach_read_from_2(undo_page + TRX_UNDO_PAGE_HDR + TRX_UNDO_PAGE_FREE);
                        ptr = undo_page + first_free;
                        ptr += 2;
                        // 记录类型
                        *ptr++ = TRX_UNDO_INSERT_REC;
                        // 记录undo表空间和table
                        ptr += mach_u64_write_much_compressed(ptr, trx->undo_no);
                        ptr += mach_u64_write_much_compressed(ptr, index->table->id);
                        // 记录主键
                        for (i = 0; i < dict_index_get_n_unique(index); i++) {
                            ptr += mach_write_compressed(ptr, flen);
                        }
                        // 记录虚拟列
                        trx_undo_report_insert_virtual(undo_page, index->table, clust_entry, &ptr);
                        // 单链表结构
                        trx_undo_page_set_next_prev_and_add(undo_page, ptr, mtr);
                    }
                    
                    // roll_ptr指向undo-log
                    *roll_ptr = trx_undo_build_roll_ptr(1, undo_ptr->rseg->space_id, page_no, offset);
                }
            }

            page_cur_tuple_insert(page_cursor, entry, index, offsets, heap, mtr);
            {
                // dtuple转物理存储格式
                rec_t *rec = rec_convert_dtuple_to_rec((byte *)mem_heap_alloc(*heap, size), index, tuple);
                {
                    rec_t *rec = buf + rec_get_converted_extra_size(data_size, n_fields, has_ext);
                    // 设置记录头
                    // [rec-bit31, rec-bit17] = 字段数
                    rec_set_n_fields_old(rec, n_fields);
                    // [rec-bit48, rec-bit45] = flag
                    rec_set_info_bits_old(rec, dtuple_get_info_bits(dtuple) & 0xF0);
                    rec_old_set_versioned(rec, false);
                    rec_set_1byte_offs_flag(rec, false);

                    // 复制每个字段的值，在记录头中记录offset
                    for (ulint i = 0; i < n_fields; i++) {
                        if (dfield_is_null(field)) {
                            len = dtype_get_sql_null_size(dfield_get_type(field), 0);
                            data_write_sql_null(rec + end_offset, len);

                            end_offset += len;
                            ored_offset = end_offset | REC_2BYTE_SQL_NULL_MASK;
                        } else {
                            len = dfield_get_len(field);
                            memcpy(rec + end_offset, dfield_get_data(field), len);

                            end_offset += len;
                            ored_offset = end_offset;

                            if (dfield_is_ext(field)) {
                                ored_offset |= REC_2BYTE_EXTERN_MASK;
                            }
                        }

                        rec_2_set_field_end_info_low(rec, i, ored_offset);
                    }
                }

                *offsets = rec_get_offsets(rec, index, *offsets, ..., heap);
                {
                    // offsets[0] = size
                    rec_offs_set_n_alloc(offsets, size);
                    // offsets[1] = n
                    rec_offs_set_n_fields(offsets, n);
                    // 计算每个字段的偏移量
                    rec_init_offsets(rec, index, offsets);
                }

                page_cur_insert_rec_low(cursor->rec, index, rec, *offsets, mtr);
                {
                    /* 1. Get the size of the physical record in the page */
                    rec_size = rec_offs_size(offsets);

                    /* 2. Try to find suitable space from page memory management */
                    free_rec = page_header_get_ptr(page, PAGE_FREE);
                    {
                        // free指向标记删除的记录构成的单链表
                        // 先尝试复用已删除记录占用的空间
                        foffsets = rec_get_offsets(free_rec, index, foffsets, ..., &heap);
                        if (rec_offs_size(foffsets) < rec_size) {
                            goto use_heap;
                        }

                        insert_buf = free_rec - rec_offs_extra_size(foffsets);
                    } else {
                    use_heap:    
                        // 从page内的空闲空间分配
                        insert_buf = page_mem_alloc_heap(page, nullptr, rec_size, &heap_no);
                    }

                    /* 3. Create the record */
                    insert_rec = rec_copy(insert_buf, rec, offsets);
                    
                    /* 4. Insert the record in the linked list of records */

                    /* next record after current before the insertion */
                    rec_t *next_rec = page_rec_get_next(current_rec);

                     // 新记录插入单链表
                    page_rec_set_next(insert_rec, next_rec);
                    page_rec_set_next(current_rec, insert_rec);

                    // 记录数加1
                    page_header_set_field(page, nullptr, PAGE_N_RECS, 1 + page_get_n_recs(page));

                    rec_set_n_owned_old(insert_rec, 0);
                    rec_set_heap_no_old(insert_rec, heap_no);

                    /* 6. Update the last insertion info in page header */
                    last_insert = page_header_get_ptr(page, PAGE_LAST_INSERT);

                    // 同一个方向连续插入: 记录插入趋势
                    if ((last_insert == current_rec) &&
                        (page_header_get_field(page, PAGE_DIRECTION) != PAGE_LEFT)) {
                        page_header_set_field(page, nullptr, PAGE_DIRECTION, PAGE_RIGHT);
                        page_header_set_field(page, nullptr, PAGE_N_DIRECTION,
                                              page_header_get_field(page, PAGE_N_DIRECTION) + 1);
                    }
                    // 最后插入的记录
                    page_header_set_ptr(page, nullptr, PAGE_LAST_INSERT, insert_rec);

                    /* 7. It remains to update the owner record. */
                    // 同一个dir-slot组内最大的记录
                    rec_t *owner_rec = page_rec_find_owner_rec(insert_rec);
                    ulint n_owned = rec_get_n_owned_old(owner_rec);
                    rec_set_n_owned_old(owner_rec, n_owned + 1);

                    // 8. 维护page末尾的稀疏索引
                    if (n_owned == PAGE_DIR_SLOT_MAX_N_OWNED) {
                        page_dir_split_slot(page, nullptr, page_dir_find_owner_slot(owner_rec));
                    }

                    /* 9. Write log record of the insert */
                    page_cur_insert_rec_write_log(insert_rec, rec_size, current_rec, index, mtr);
                }
            }

            // 更新适应性hash索引
            if (!index->disable_ahi) {
                if (!reorg && leaf && (cursor->flag == BTR_CUR_HASH)) {
                    btr_search_update_hash_node_on_insert(cursor);
                } else {
                    btr_search_update_hash_on_insert(cursor);
                }
            }
        }
    } else {
        err = btr_cur_optimistic_insert(flags, cursor, &offsets, &offsets_heap,
                                        entry, &insert_rec, &big_rec, thr, &mtr);
        if (err == DB_FAIL) {
            btr_cur_pessimistic_insert(flags, cursor, &offsets, &offsets_heap,
                                       entry, &insert_rec, &big_rec, thr, &mtr);
            {
                // 加gap锁和插入意向锁
                btr_cur_ins_lock_and_undo(flags, cursor, entry, thr, mtr, ...);

                // 记录太长需要页外存储
                if (page_zip_rec_needs_ext(rec_get_converted_size(index, entry),
                                        dict_table_is_comp(index->table),
                                        dtuple_get_n_fields(entry),
                                        dict_table_page_size(index->table))) {
                    big_rec_vec = dtuple_convert_big_rec(index, nullptr, entry);
                }

                if (dict_index_get_page(index) == btr_cur_get_block(cursor)->page.id.page_no()) {
                    /* The page is the root page */
                    // 当前tree只有root一个节点: 分隔当前节点，分隔点插入新的root节点
                    *rec = btr_root_raise_and_insert(flags, cursor, offsets, heap, entry, mtr);
                } else {
                    // 节点拆分: 递归处理tree结构变更
                    *rec = btr_page_split_and_insert(flags, cursor, offsets, heap, entry, mtr);
                }
            }
        }
    }

    // 超长记录页外存储
    if (big_rec != nullptr) {
        row_ins_index_entry_big_rec(thr_get_trx(thr), entry, big_rec, offsets, ...);
        {
            lob::btr_store_big_rec_extern_fields(
                    trx, &pcur, nullptr, offsets, big_rec, &mtr, lob::OPCODE_INSERT);
        }
    }
}
```

## 更新

```c
int ha_innobase::update_row(const uchar *old_row, uchar *new_row) {

    upd_t *uvect = m_prebuilt->upd_node->update;
    // 计算发生变化的字段信息
    calc_row_difference(uvect, old_row, new_row, table, m_upd_buf,
                        m_upd_buf_size, m_prebuilt, m_user_thd);
    
    row_update_for_mysql((byte *)old_row, m_prebuilt);
    {
        node = prebuilt->upd_node;
        node->state = UPD_NODE_UPDATE_CLUSTERED;
        row_upd_step(thr);
        {
            if (node->state == UPD_NODE_SET_IX_LOCK) {
                lock_table(0, node->table, LOCK_IX, thr);
                node->state = UPD_NODE_UPDATE_CLUSTERED;
            }

            row_upd(node, thr);
            {
                // 更新聚集索引
                row_upd_clust_step(node, thr);
                {
                    // 定位在待修改的记录
                    pcur->restore_position(mode, &mtr, ...);
                    // 获取记录信息: 字段偏移
                    offsets = rec_get_offsets(rec, index, offsets_, ...);

                    // 加记录锁
                    lock_clust_rec_modify_check_and_lock(flags, pcur->get_block(), rec, index, offsets, thr);
                    {
                        lock_rec_lock(true, SELECT_ORDINARY, LOCK_X | LOCK_REC_NOT_GAP, block, heap_no, index, thr);
                    }

                    if (node->is_delete) {
                        // 设置标记删除标识位
                        row_upd_del_mark_clust_rec(flags, node, index, offsets, thr, ..., &mtr);
                    }

                    if (node->cmpl_info & UPD_NODE_NO_ORD_CHANGE) {
                        // 没有修改索引字段
                        row_upd_clust_rec(flags, node, index, offsets, &heap, thr, &mtr);
                        {
                            if (node->cmpl_info & UPD_NODE_NO_SIZE_CHANGE) {
                                // 字段长度未变直接原地修改
                                err = btr_cur_update_in_place(flags | BTR_NO_LOCKING_FLAG, btr_cur, offsets, ..., mtr);
                            } else {
                                // 先尝试只修改叶子节点: 没有页外储存的字段且当前页空间充足
                                err = btr_cur_optimistic_update(flags | BTR_NO_LOCKING_FLAG, btr_cur, &offsets, offsets_heap, ..., mtr);
                                {
                                    btr_cur_upd_lock_and_undo(flags, cursor, *offsets, update, cmpl_info, thr, mtr, &roll_ptr);
                                    {
                                        lock_clust_rec_modify_check_and_lock(...);
                                        trx_undo_report_row_operation(...);
                                        {
                                            offset = trx_undo_page_report_modify(undo_page, trx, index, rec, offsets, ..., &mtr);
                                            {
                                                first_free = mach_read_from_2(undo_page + TRX_UNDO_PAGE_HDR + TRX_UNDO_PAGE_FREE);
                                                ptr = undo_page + first_free;

                                                // 变更类型: 更新或删除
                                                *ptr++ = (byte)type_cmpl;
                                                *ptr++ = 0x00;

                                                // 写入undo表空间
                                                ptr += mach_u64_write_much_compressed(ptr, trx->undo_no);
                                                // 写入数据表
                                                ptr += mach_u64_write_much_compressed(ptr, table->id);
                                                // 保存记录头中的flag信息: (rec-6)&0xF0
                                                *ptr++ = (byte)rec_get_info_bits(rec, dict_table_is_comp(table));

                                                // 保存原记录的trx_id
                                                field = rec_get_nth_field(nullptr, rec, offsets, index->get_sys_col_pos(DATA_TRX_ID), &flen);
                                                trx_id = trx_read_trx_id(field);
                                                ptr += mach_u64_write_compressed(ptr, trx_id);

                                                // 保存原记录的roll_ptr: 维持版本链
                                                field = rec_get_nth_field(nullptr, rec, offsets, index->get_sys_col_pos(DATA_ROLL_PTR), &flen);
                                                ptr += mach_u64_write_compressed(ptr, trx_read_roll_ptr(field));

                                                // 记录主键
                                                for (i = 0; i < dict_index_get_n_unique(index); i++) {
                                                    ptr += mach_write_compressed(ptr, flen);
                                                }

                                                if (update) {
                                                    // 保存变更的字段数量
                                                    ptr += mach_write_compressed(ptr, n_updated);
                                                    // 保存变更的字段值
                                                    for (i = 0; i < upd_get_n_fields(update); i++) {
                                                        ptr += mach_write_compressed(ptr, flen);
                                                    }
                                                }

                                                // 修改了索引字段
                                                if (!update || !(cmpl_info & UPD_NODE_NO_ORD_CHANGE)) {
                                                    // 保存所有的索引字段的原值
                                                    for (col_no = 0; col_no < table->get_n_cols(); col_no++) {
                                                        if (col->ord_part) {
                                                            ptr += mach_write_compressed(ptr, pos);
                                                        }
                                                    }
                                                }
                                            }

                                            // roll_ptr指向undo-log
                                            *roll_ptr = trx_undo_build_roll_ptr(0, undo_ptr->rseg->space_id, page_no, offset);
                                        }
                                    }
                                    page_cur_delete_rec(page_cursor, index, *offsets, mtr);
                                    btr_cur_insert_if_possible(cursor, new_entry, offsets, heap, mtr);
                                }
                            }

                            // 简单方式不成功尝试复杂的方式：可能需要分配新的page，修改索引节点
                            if (err != DB_SUCCESS) {
                                big_rec_t *big_rec = nullptr;
                                btr_cur_pessimistic_update(
                                    flags | BTR_NO_LOCKING_FLAG | BTR_KEEP_POS_FLAG, btr_cur, &offsets,
                                    offsets_heap, heap, &big_rec, node->update, node->cmpl_info, thr, trx_id,
                                    trx->undo_no, mtr);
                                if (big_rec) {
                                    lob::btr_store_big_rec_extern_fields(trx, pcur, node->update, offsets, big_rec, mtr, lob::OPCODE_UPDATE);
                                }
                            }
                        }
                    } else {
                        // 修改了索引字段: 为了避免mvcc时查不到记录，不能原地修改，必须先标记删除再重新插入
                        row_upd_clust_rec_by_insert(flags, node, index, thr, referenced, &mtr);
                        // 先标记删除
                        btr_cur_del_mark_set_clust_rec(flags, btr_cur_get_block(btr_cur), rec,
                                                       index, offsets, thr, node->row, mtr);
                        // 重新插入
                        search_result = row_ins_clust_index_entry(index, entry, thr, false);
                        if (search_result == ROW_FOUND) {
                            // 找到之后先删除: 不能直接更新，否则mvcc就找不到了
                            if (!rec_get_deleted_flag(rec, false)) {
                                btr_cur_del_mark_set_sec_rec(flags, btr_cur, true, thr, &mtr);
                            }

                            /* Build a new index entry */
                            entry = row_build_index_entry(node->upd_row, node->upd_ext, index, heap);

                            /* Insert new index entry */
                            row_ins_sec_index_entry(index, entry, thr, false);
                            {
                                err = row_ins_sec_index_entry_low(flags, BTR_MODIFY_LEAF, index, ...);
                                if (err == DB_FAIL) {
                                    row_ins_sec_index_entry_low(flags, BTR_MODIFY_TREE, index, ...);
                                }
                            }
                        }
                    }
                }

                do {
                    // 更新每个二级索引
                    row_upd_sec_step(node, thr);
                    {
                        row_upd_sec_index_entry(node, thr);
                        {
                            // 先定位到待更新的记录
                            row_search_index_entry(index, entry, mode, &pcur, &mtr);
                        }
                    }

                    node->index = node->index->next();
                } while (node->index != nullptr);
            }
        }
    }
}
```

## 查询

![b+tree](/assets/images/2023-02-12/b+tree.png)

```c
int ha_innobase::index_read(uchar *buf, const uchar *key_ptr, uint key_len, ...) {
    
    // 转换搜索key的格式
    row_sel_convert_mysql_key_to_innobase(
        m_prebuilt->search_tuple, m_prebuilt->srch_key_val1,
        m_prebuilt->srch_key_val_len, index, key_ptr, key_len);

    row_search_mvcc(buf, mode, m_prebuilt, match_mode, 0);
    {
        /* PHASE 1: Try to pop the row from the record buffer or from the prefetch cache */
        if (direction == prebuilt->fetch_direction &&  prebuilt->n_fetch_cached > 0) {
            row_sel_dequeue_cached_row_for_mysql(buf, prebuilt);
            return DB_SUCCESS;
        }

        // 使用索引字段精准查询非空唯一索引
        if (match_mode == ROW_SEL_EXACT && dict_index_is_unique(index) &&
            dtuple_get_n_fields(search_tuple) == dict_index_get_n_unique(index) &&
            (index->is_clustered() || !dtuple_contains_null(search_tuple))) {
            unique_search = true;
        }

        /* PHASE 2: Try fast adaptive hash index search if possible */
        if (unique_search && index->is_clustered() 
            && !prebuilt->templ_contains_blob
            && (prebuilt->mysql_row_len < UNIV_PAGE_SIZE / 8)) {
            
        }

        if (prebuilt->select_lock_type == LOCK_NONE) {
            // 创建mvcc视图
            trx_assign_read_view(trx);
            {
                trx_sys->mvcc->view_open(trx->read_view, trx);
                {
                    read_view->prepare(trx->id);
                    {
                        // 连续的已提交的最大事务: 在此之前的记录都可见
                        m_low_limit_no = trx_get_serialisation_min_trx_no();
                        // 当前最大事务: 在此之后都不可见
                        m_low_limit_id = trx_sys_get_next_trx_id_or_no();
                        // 复制所有未提交的事务
                        if (!trx_sys->rw_trx_ids.empty()) {
                            copy_trx_ids(trx_sys->rw_trx_ids);
                        }
                        // 最小的未提交的事务
                        m_up_limit_id = !m_ids.empty() ? m_ids.front() : m_low_limit_id;
                    }
                }
            }
        } else {
            // 加意向锁
            lock_table(0, index->table,
                     prebuilt->select_lock_type == LOCK_S ? LOCK_IS : LOCK_IX, ...);
        }

        // 定位到叶子节点中指定的字段值
        /* PHASE 3: Open or restore index cursor position */
        pcur->open_no_init(index, search_tuple, mode, BTR_SEARCH_LEAF, 0, &mtr, ...);

        // 加间隙锁
        sel_set_rec_lock(pcur, next_rec, index, offsets, ..., LOCK_GAP, thr, &mtr);

        /* PHASE 4: Look for matching records in a loop */
        rec = pcur->get_rec();

        if (page_rec_is_infimum(rec)) {
            prev_rec = nullptr;
            goto next_rec;
        }

        if (page_rec_is_supremum(rec)) {
            if (prev_rec != nullptr) {
                if (row_search_end_range_check(...)) {
                    err = DB_RECORD_NOT_FOUND;
                    goto normal_return;
                }
            }

            // 加next-key锁
            sel_set_rec_lock(pcur, rec, index, offsets, ..., LOCK_ORDINARY, thr, &mtr);
            prev_rec = nullptr;
            goto next_rec;
        }

        next_offs = rec_get_next_offs(rec, false);
        offsets = rec_get_offsets(rec, index, offsets, ...);

        if (match_mode == ROW_SEL_EXACT) {
            if (0 != cmp_dtuple_rec(search_tuple, rec, index, offsets)) {
                // 加间隙锁
                sel_set_rec_lock(pcur, rec, index, offsets, ..., LOCK_GAP, thr, &mtr);
                err = DB_RECORD_NOT_FOUND;
                goto normal_return;
            }
        } else if (match_mode == ROW_SEL_EXACT_PREFIX) {
            if (!cmp_dtuple_is_prefix_of_rec(search_tuple, rec, index, offsets)) {
                // 加间隙锁
                sel_set_rec_lock(pcur, rec, index, offsets, ..., LOCK_GAP, thr, &mtr);
                err = DB_RECORD_NOT_FOUND;
                goto normal_return;
            }
        }

        if (prebuilt->select_lock_type == LOCK_NONE) {
            if (trx->isolation_level == TRX_ISO_READ_UNCOMMITTED) {
                // Do nothing
            } else if (index == clust_index) {
                // 如果看不到当前记录，查找之前的版本
                visable = lock_clust_rec_cons_read_sees(rec, index, offsets, read_view);
                {
                    // 读取因此列trx_id
                    trx_id_t trx_id = row_get_rec_trx_id(rec, index, offsets);
                    return read_view->changes_visible(trx_id, index->table->name);
                    {
                        if (id < m_up_limit_id || id == m_creator_trx_id) {
                            return (true);
                        }

                        if (id >= m_low_limit_id) {
                            return (false);
                        } else if (m_ids.empty()) {
                            return (true);
                        }

                        return (!std::binary_search(p, p + m_ids.size(), id));
                    }
                }

                if (! visable) {
                    rec_t *old_vers;
                    // 查找之前的版本
                    row_sel_build_prev_vers_for_mysql(
                                trx->read_view, clust_index, prebuilt, rec, &offsets, ..., &mtr,
                                prebuilt->get_lob_undo());
                    {
                        version = rec;
                        for (;;) {
                            // 当前的trx_id
                            version_trx_id = row_get_rec_trx_id(version, index, *offsets);
                            if (rec == version) {
                                rec_trx_id = version_trx_id;
                            }

                            // 判断事务是否已提交
                            if (!trx_rw_is_active(version_trx_id, false)) {
                                if (rec == version) {
                                    *old_vers = rec;
                                    break;
                                }

                                buf = mem_heap_alloc(in_heap, rec_offs_size(*offsets));
                                // 复制数据
                                *old_vers = rec_copy(buf, version, *offsets);
                                rec_offs_make_valid(*old_vers, index, *offsets);
                            }

                            // 构造前一个版本
                            trx_undo_prev_version_build(rec, mtr, version, index, *offsets, ...);
                            {
                                roll_ptr = row_get_rec_roll_ptr(rec, index, offsets);

                                if (trx_undo_roll_ptr_is_insert(roll_ptr)) {
                                    /* The record rec is the first inserted version */
                                    return true;
                                }

                                rec_trx_id = row_get_rec_trx_id(rec, index, offsets);
                                trx_undo_get_undo_rec(roll_ptr, rec_trx_id, ..., &undo_rec);
                                {
                                    trx_undo_decode_roll_ptr(roll_ptr, &is_insert, &rseg_id, &page_no, &offset);
                                    undo_page = trx_undo_page_get_s_latched(page_id_t(space_id, page_no), page_size, &mtr);

                                    undo_rec = trx_undo_rec_copy(undo_page, static_cast<uint32_t>(offset), heap);
                                }

                                // 读取undo-log
                                ptr = trx_undo_rec_get_pars(undo_rec, &type, ...);
                                // 读取undo-log中的trx_id和roll_ptr
                                ptr = trx_undo_update_rec_get_sys_cols(ptr, &trx_id, &roll_ptr, ...);
                                // 合并更新的字段
                                ptr = trx_undo_update_rec_get_update(ptr, index, type, trx_id, roll_ptr, ...);

                                if (row_upd_changes_field_size_or_external(index, offsets, update)) {
                                    // 先标记删除后插入的反向操作
                                } else {
                                    // 原地修改的反向操作
                                    buf = mem_heap_alloc(heap, rec_offs_size(offsets));
                                    *old_vers = rec_copy(buf, rec, offsets);
                                    rec_offs_make_valid(*old_vers, index, offsets);
                                    row_upd_rec_in_place(*old_vers, index, offsets, update, nullptr);
                                }
                            }
                        }
                    }
                    
                    if (old_vers == nullptr) {
                        goto next_rec;
                    }

                    rec = old_vers;
                    prev_rec = rec;
                }
            } else {
                // 二级索引
                if (!lock_sec_rec_cons_read_sees(rec, index, trx->read_view)) {
                    res = row_search_idx_cond_check(buf, prebuilt, rec, offsets);
                    switch (res) {
                        case ICP_NO_MATCH:
                            goto next_rec;
                        case ICP_OUT_OF_RANGE:
                            err = DB_RECORD_NOT_FOUND;
                            goto idx_cond_failed;
                        case ICP_MATCH:
                            goto requires_clust_rec;
                    }
                }
            }

            // 匹配的记录已删除
            if (rec_get_deleted_flag(rec, comp)) {
                if (index == clust_index && unique_search) {
                    err = DB_RECORD_NOT_FOUND;
                    goto normal_return;
                }

                goto next_rec;
            }

            /* Check if the record matches the index condition. */
            switch (row_search_idx_cond_check(buf, prebuilt, rec, offsets)) {
                case ICP_NO_MATCH:
                    prebuilt->try_unlock(true);
                    goto next_rec;
                case ICP_OUT_OF_RANGE:
                    err = DB_RECORD_NOT_FOUND;
                    prebuilt->try_unlock(true);
                    goto idx_cond_failed;
                case ICP_MATCH:
                    break;
            }

            // 匹配成功: 转换记录格式
            row_sel_store_mysql_rec(buf, prebuilt, result_rec, ...)

        next_rec:
            if (moves_up) {
                // 下一条记录
                bool move = pcur->move_to_next(&mtr);
                
                if (!move) {
                not_moved:
                    pcur->store_position(&mtr);
                    
                    if (match_mode != 0) {
                        err = DB_RECORD_NOT_FOUND;
                    } else {
                        err = DB_END_OF_INDEX;
                    }

                    goto normal_return;
                }
            } else {
                // 前一条记录
                if (!pcur->move_to_prev(&mtr)) {
                    goto not_moved;
                }
            }

            goto rec_loop;

        }
    }
}
```