---
layout: post
title:  "zookeeper"
date:   2023-04-03 01:22:07 +0000
categories: jekyll
tags: zookeeper
---

# zookeeper单节点

## 启动过程

```java

public static void main(String[] args) {

    initializeAndRun(args);
    {
        // 配置文件解析
        ServerConfig config = new ServerConfig();
        if (args.length == 1) {
            config.parse(args[0]);
        } else {
            config.parse(args);
        }

        runFromConfig(config);
        {
            // 读写snap和log
            FileTxnSnapLog snapLog = new FileTxnSnapLog(config.dataLogDir, config.dataDir);
            final ZooKeeperServer zks = new ZooKeeperServer(..., snapLog, config.tickTime, ...);

            cnxnFactory = ServerCnxnFactory.createFactory();
            cnxnFactory.configure(config.getClientPortAddress(), ...);
            {
                // 处理idle连接，默认10s超时
                cnxnExpiryQueue = new ExpiryQueue<NIOServerCnxn>(sessionlessCnxnTimeout);
                expirerThread = new ConnectionExpirerThread();

                // 处理client的连接
                for (int i = 0; i < numSelectorThreads; ++i) {
                    selectorThreads.add(new SelectorThread(i));
                }

                // 绑定端口
                ss = ServerSocketChannel.open();
                ss.socket().setReuseAddress(true);
                ss.socket().bind(addr, listenBacklog);
                ss.configureBlocking(false);

                // 接收client的连接
                acceptThread = new AcceptThread(ss, addr, selectorThreads);
            }

            cnxnFactory.startup(zks);
            {
                start();
                {
                    // executor线程池处理io
                    workerPool = new WorkerService("NIOWorker", numWorkerThreads, false);
                    {
                        workers.add(Executors.newFixedThreadPool(numWorkerThreads, ...));
                    }

                    for (SelectorThread thread : selectorThreads) {
                        thread.start();
                    }

                    // 接收client连接
                    acceptThread.start();

                    // 定时清理idle链接
                    expirerThread.start();
                }

                zks.setServerCnxnFactory(this);

                zks.startdata();
                {
                    zkDb = new ZKDatabase(this.txnLogFactory);
                    // 从磁盘恢复数据
                    loadData();
                }

                zks.startup();
                {
                    // 清理过期的瞬时节点
                    sessionTracker = new SessionTrackerImpl(this, zkDb.getSessionWithTimeOuts(), tickTime, ...);
                    sessionTracker.start();

                    setupRequestProcessors();
                    {
                        RequestProcessor finalProcessor = new FinalRequestProcessor(this);
                        RequestProcessor syncProcessor = new SyncRequestProcessor(this, finalProcessor);
                        ((SyncRequestProcessor) syncProcessor).start();
                        firstProcessor = new PrepRequestProcessor(this, syncProcessor);
                        ((PrepRequestProcessor) firstProcessor).start();
                    }

                    // 控制请求速度
                    requestThrottler = createRequestThrottler();
                    requestThrottler.start();
                }
            }
        }
    }

}

```

数据结构

```java

 // information explicitly stored by the server persistently
class StatPersisted {
    long czxid;             // created zxid
    long mzxid;             // last modified zxid
    long ctime;             // created
    long mtime;             // last modified
    int version;            // version
    int cversion;           // child version
    int aversion;           // acl version
    long ephemeralOwner;    // owner id if ephemeral, 0 otw
    long pzxid;             // last modified children
}

public class DataNode {

    /** the data for this datanode */
    byte[] data;

    /**
     * the acl map long for this datanode. the datatree has the map
     */
    Long acl;

    /**
     * the stat for this node that is persisted to disk.
     */
    public StatPersisted stat;

    // 子节点名称
    private Set<String> children;

}

public class DataTree {

    // root节点
    private DataNode root = new DataNode(new byte[0], -1L, new StatPersisted());
    private static final String rootZookeeper = "/";

    DataTree() {
        nodes = new NodeHashMapImpl(...);
        {
            // 存储每个path(绝对路径)对应的node
            nodes = new ConcurrentHashMap<String, DataNode>();
        }

        // ""是/的别名
        nodes.put("", root);
        nodes.putWithoutDigest(rootZookeeper, root);

         /** add the proc node and quota node */
        root.addChild(procChildZookeeper);
        nodes.put(procZookeeper, procDataNode);

        procDataNode.addChild(quotaChildZookeeper);
        nodes.put(quotaZookeeper, quotaDataNode);
    }

}

public void startdata() {

    zkDb = new ZKDatabase(this.txnLogFactory);
    {
        // 内存数据结构
        dataTree = new DataTree();
        // 瞬时节点的超时时间
        sessionsWithTimeouts = new ConcurrentHashMap<Long, Integer>();
        this.snapLog = snapLog;
    }

    loadData();
    {
        zkDb.loadDataBase();
        {
            snapLog.restore(dt, sessionsWithTimeouts, ...);
            {
                // 加载snap
                snapLog.deserialize(dt, sessions);
                {
                    // 按文件名倒排，前100个snap文件
                    List<File> snapList = findNValidSnapshots(100);
                    for (int i = 0, snapListSize = snapList.size(); i < snapListSize; i++) {
                        snap = snapList.get(i);
                        snapZxid = Util.getZxidFromName(snap.getName(), SNAPSHOT_FILE_PREFIX);
                        try (CheckedInputStream snapIS = SnapStream.getInputStream(snap)) {
                            InputArchive ia = BinaryInputArchive.getArchive(snapIS);

                            deserialize(dt, sessions, ia);
                            {
                                FileHeader header = new FileHeader();
                                header.deserialize(ia, "fileheader");
                                if (header.getMagic() != SNAP_MAGIC) {
                                    throw new IOException("mismatching magic headers");
                                }

                                SerializeUtils.deserializeSnapshot(dt, ia, sessions);
                                {
                                    // 先解析瞬时节点的timeout
                                    int count = ia.readInt("count");
                                    while (count > 0) {
                                        long id = ia.readLong("id");
                                        int to = ia.readInt("timeout");
                                        sessions.put(id, to);
                                        count--;
                                    }

                                    dt.deserialize(ia, "tree");
                                    {
                                        // 解析acl
                                        aclCache.deserialize(ia);

                                        // 读取lv格式的字符串
                                        String path = ia.readString("path");

                                        // 末尾是字符串/
                                        while (!"/".equals(path)) {
                                            DataNode node = new DataNode();
                                            ia.readRecord(node, "node");
                                            nodes.put(path, node);
                                            synchronized (node) {
                                                aclCache.addUsage(node.acl);
                                            }

                                            // root的path是""
                                            int lastSlash = path.lastIndexOf('/');
                                            if (lastSlash == -1) {
                                                root = node;
                                            } else {
                                                // 先解析parent再解析child
                                                String parentPath = path.substring(0, lastSlash);
                                                DataNode parent = nodes.get(parentPath);
                                                if (parent == null) {
                                                    throw new IOException("Invalid Datatree");
                                                }
                                                parent.addChild(path.substring(lastSlash + 1));

                                                // 处理瞬时节点
                                                long eowner = node.stat.getEphemeralOwner();
                                                EphemeralType ephemeralType = EphemeralType.get(eowner);
                                                if (ephemeralType == EphemeralType.CONTAINER) {
                                                    containers.add(path);
                                                } else if (ephemeralType == EphemeralType.TTL) {
                                                    ttls.add(path);
                                                } else if (eowner != 0) {
                                                    HashSet<String> list = ephemerals.get(eowner);
                                                    list.add(path);
                                                }
                                            }

                                            path = ia.readString("path");
                                        }
                                    }
                                }
                            }

                            foundValid = true;
                            break;
                        }
                    }
                }

                // 从snap的最大log开始replay
                fastForwardFromEdits(dt, sessions, listener);
                {
                    TxnIterator itr = txnLog.read(dt.lastProcessedZxid + 1);
                    {
                        return new FileTxnIterator(logDir, zxid, fastForward);
                        {
                            init();
                            {
                                // 读取所有log文件，按zxid倒排
                                storedFiles = new ArrayList<>();
                                List<File> files = Util.sortDataDir(FileTxnLog.getLogFiles(logDir.listFiles(), 0), LOG_FILE_PREFIX, false);
                                
                                // 收集覆盖指定zxid的所有log
                                for (File f : files) {
                                    if (Util.getZxidFromName(f.getName(), LOG_FILE_PREFIX) >= zxid) {
                                        storedFiles.add(f);
                                    } else if (Util.getZxidFromName(f.getName(), LOG_FILE_PREFIX) < zxid) {
                                        // add the last logfile that is less than the zxid
                                        storedFiles.add(f);
                                        break;
                                    }
                                }

                                // 打开第一个log文件
                                goToNextLog();
                                // 解析一条记录
                                next();
                            }

                            // 定位到指定zxid
                            while (hdr.getZxid() < zxid) {
                                if (!next()) {
                                    break;
                                }
                            }
                        }
                    }

                    TxnHeader hdr;

                    while (true) {
                        hdr = itr.getHeader();
                        processTransaction(hdr, dt, sessions, itr.getTxn());
                        {
                            dt.processTxn(hdr, txn);
                            {
                                switch (header.getType()) {
                                case OpCode.create:
                                    createNode(...);
                                    break;

                                case OpCode.setData:
                                    setData(...);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Clean up dead sessions
        zkDb.getSessions().stream()
                        .filter(session -> zkDb.getSessionWithTimeOuts().get(session) == null)
                        .forEach(session -> killSession(session, zkDb.getDataTreeLastProcessedZxid()));

        // Make a clean snapshot
        takeSnapshot();
        {
            snapLog.save(zkDb.getDataTree(), zkDb.getSessionWithTimeOuts(), ...);
            {
                // 加载snap的反向操作
            }
        }
    }
}

```

---

session追踪线程

```java

public class SessionTrackerImpl {

    public SessionTrackerImpl(SessionExpirer expirer, ConcurrentMap<Long, Integer> sessionsWithTimeout, int tickTime, ...) {
        this.expirer = expirer;
        // tickTime默认2s
        this.sessionExpiryQueue = new ExpiryQueue<SessionImpl>(tickTime);
        {
            // 所有session的超时时长都向上取整按2s分桶
            // elemMap存储每个session的超时时刻
            ConcurrentHashMap<E, Long> elemMap = new ConcurrentHashMap<E, Long>();
            // expiryMap存储每个超时时刻的session集合
            ConcurrentHashMap<Long, Set<E>> expiryMap = new ConcurrentHashMap<Long, Set<E>>();
        }

        // 开始追踪从磁盘恢复过来的瞬时节点
        for (Entry<Long, Integer> e : sessionsWithTimeout.entrySet()) {
            trackSession(e.getKey(), e.getValue());
        }
    }

     public void run() {
        while (running) {
            // 等待一个分桶的时长
            long waitTime = sessionExpiryQueue.getWaitTime();
            if (waitTime > 0) {
                Thread.sleep(waitTime);
                continue;
            }

            for (SessionImpl s : sessionExpiryQueue.poll()) {
                setSessionClosing(s.sessionId);
                expirer.expire(s);
                {
                    long sessionId = session.getSessionId();
                    // 提交closeSession请求，删除瞬时节点，通知watcher
                    Request si = new Request(null, sessionId, 0, OpCode.closeSession, ...);
                    submitRequest(si);
                }
            }
        }
    }
}

```

---

请求处理流程

![zk-thread](/assets/images/2023-04-03/zk-thread.png)

接收client连接的线程

```java

private class AcceptThread {

    public AcceptThread(ServerSocketChannel ss, InetSocketAddress addr, Set<SelectorThread> selectorThreads) {
        this.acceptSocket = ss;
        // 注册OP_ACCEPT事件
        this.acceptKey = acceptSocket.register(selector, SelectionKey.OP_ACCEPT);
        this.selectorThreads = new ArrayList<SelectorThread>(selectorThreads);
        selectorIterator = this.selectorThreads.iterator();
    }

    public void run() {
        while (!stopped && !ss.socket().isClosed()) {
            selector.select();

            Iterator<SelectionKey> selectedKeys = selector.selectedKeys().iterator();
            while (!stopped && selectedKeys.hasNext()) {
                SelectionKey key = selectedKeys.next();
                selectedKeys.remove();

                if (key.isAcceptable()) {
                    SocketChannel sc = acceptSocket.accept();
                    sc.configureBlocking(false);

                    // 轮流选择SelectorThread处理连接
                    SelectorThread selectorThread = selectorIterator.next();
                    selectorThread.addAcceptedConnection(sc);
                    {
                        acceptedQueue.offer(accepted);
                        selector.wakeup();
                    }
                }
            }
        }
    }

}

```

client连接处理线程

```java

public class SelectorThread {

    public SelectorThread(int id) {
        this.id = id;
        acceptedQueue = new LinkedBlockingQueue<SocketChannel>();
        updateQueue = new LinkedBlockingQueue<SelectionKey>();
    }

    public void run() {
        while (!stopped) {
            select();
            {
                selector.select();

                Set<SelectionKey> selected = selector.selectedKeys();
                ArrayList<SelectionKey> selectedList = new ArrayList<SelectionKey>(selected);
                Collections.shuffle(selectedList);
                Iterator<SelectionKey> selectedKeys = selectedList.iterator();
                while (!stopped && selectedKeys.hasNext()) {
                    SelectionKey key = selectedKeys.next();
                    selected.remove(key);

                    if (key.isReadable() || key.isWritable()) {
                        handleIO(key);
                        {
                            IOWorkRequest workRequest = new IOWorkRequest(this, key);
                            NIOServerCnxn cnxn = (NIOServerCnxn) key.attachment();

                            // 处理请求/发送响应期间停止select
                            cnxn.disableSelectable();
                            key.interestOps(0);

                            // 任何操作都刷新idle超时时间
                            touchCnxn(cnxn);

                            // 交给线程池处理
                            workerPool.schedule(workRequest);
                        }
                    }
                }
            }

            // 处理accepted的客户端连接
            processAcceptedConnections();
            {
                while (!stopped && (accepted = acceptedQueue.poll()) != null) {
                    // 注册OP_READ事件
                    SelectionKey key = accepted.register(selector, SelectionKey.OP_READ);

                    NIOServerCnxn cnxn = createConnection(accepted, key, this);
                    key.attach(cnxn);

                    // 追踪idle连接，10s无操作则关闭
                    addCnxn(cnxn);
                    {
                        cnxnExpiryQueue.update(cnxn, cnxn.getSessionTimeout());
                    }
                }
            }

            // 修改selector事件类型
            processInterestOpsUpdateRequests();
            {
                while (!stopped && (key = updateQueue.poll()) != null) {
                    NIOServerCnxn cnxn = (NIOServerCnxn) key.attachment();
                    if (cnxn.isSelectable()) {
                        key.interestOps(cnxn.getInterestOps());
                    }
                }
            }
        }
    }

}

```

IO处理线程

```java

private class IOWorkRequest {

    IOWorkRequest(SelectorThread selectorThread, SelectionKey key) {
        this.selectorThread = selectorThread;
        this.key = key;
        this.cnxn = (NIOServerCnxn) key.attachment();
    }

    public void doWork() {
         if (key.isReadable() || key.isWritable()) {
            // #zk#3.2.1c cnxn.doIO(key)
            cnxn.doIO(key);
            {
                if (k.isReadable()) {
                    int rc = sock.read(incomingBuffer);
                    
                    // incomingBuffer初始长度是4，用于接收一条命令的长度
                    if (incomingBuffer.remaining() == 0) {
                        boolean isPayload;
                        if (incomingBuffer == lenBuffer) {
                            incomingBuffer.flip();

                            // 每条指令都以4字节的长度开始
                            isPayload = readLength(k);
                            {
                                int len = lenBuffer.getInt();
                                incomingBuffer = ByteBuffer.allocate(len);
                            }

                            incomingBuffer.clear();
                        } else {
                            // continuation
                            isPayload = true;
                        }

                        if (! isPayload) {
                            return;  
                        } 

                        // 读取指定长度的payload
                        readPayload();
                        {
                            if (incomingBuffer.remaining() != 0) {
                                sock.read(incomingBuffer);
                            }

                            // 收到一条完整的指令
                            if (incomingBuffer.remaining() == 0) {
                                incomingBuffer.flip();

                                if (!initialized) {
                                    // 处理connect命令: client连接的第一条命令
                                    readConnectRequest();
                                } else {
                                    // 解析并处理请求
                                    readRequest();
                                    {
                                        zkServer.processPacket(this, incomingBuffer);
                                        {
                                            InputStream bais = new ByteBufferInputStream(incomingBuffer);
                                            BinaryInputArchive bia = BinaryInputArchive.getArchive(bais);
                                            // 解析header: 包含指令类型type
                                            RequestHeader h = new RequestHeader();
                                            h.deserialize(bia, "header");

                                            if (h.getType() == OpCode.auth) {
                                                // auth指令
                                            } else {
                                                Request si = new Request(cnxn, cnxn.getSessionId(), h.getXid(), h.getType(), incomingBuffer, cnxn.getAuthInfo());
                                                si.setOwner(ServerCnxn.me);
                                                submitRequest(si);
                                                {
                                                    // 进入限速线程
                                                    requestThrottler.submitRequest(si);
                                                }
                                            }
                                        }
                                    }
                                }

                                lenBuffer.clear();

                                // 准备接收下一条指令的4字节长度
                                incomingBuffer = lenBuffer;
                            }
                        }
                    }
                }
                if (k.isWritable()) {
                    // 发送outgoingBuffers中的响应数据
                    handleWrite(k);
                    {
                        ByteBuffer[] bufferList = new ByteBuffer[outgoingBuffers.size()];
                        sock.write(outgoingBuffers.toArray(bufferList));

                        // Remove the buffers that we have sent
                        ByteBuffer bb;
                        while ((bb = outgoingBuffers.peek()) != null) {
                            if (bb == packetSentinel) {
                                // 标识一个完整的响应发送完毕
                            }
                            // 没有发送完，等下次继续
                            if (bb.remaining() > 0) {
                                break;
                            }
                            // 删除发送完的buf
                            outgoingBuffers.remove();
                        }
                    }
                }
            }

            // 更新idle连接超时计时器
            touchCnxn(cnxn);
        }

        // Mark this connection as once again ready for selection
        cnxn.enableSelectable();
        selectorThread.addInterestOpsUpdateRequest(key);
        {
            // 更新selector事件
            updateQueue.offer(sk);
        }
    }

}

```

限速线程

```java

public class RequestThrottler {

    // 请求队列
    private final LinkedBlockingQueue<Request> submittedRequests = new LinkedBlockingQueue<Request>();

    // 最大并发请求
    private static volatile int maxRequests = Integer.getInteger("zookeeper.request_throttle_max_requests", 0);

    public RequestThrottler(ZooKeeperServer zks) {
        this.zks = zks;
    }

    public void run() {
        while (true) {
            Request request = submittedRequests.take();

            if (maxRequests > 0) {
                while (true) {
                    if (zks.getInProcess() < maxRequests) {
                        break;
                    }
                    // 等待现有请求完成
                    throttleSleep(stallTime);
                }
            }

            // 提交到请求链
            zks.submitRequestNow(request);
        }
    }

}

```


## 请求处理链

```java

public interface RequestProcessor {

    void processRequest(Request request);

}

public class ZooKeeperServer {

    protected RequestProcessor firstProcessor;

    protected void setupRequestProcessors() {
        RequestProcessor finalProcessor = new FinalRequestProcessor(this);
        RequestProcessor syncProcessor = new SyncRequestProcessor(this, finalProcessor);
        ((SyncRequestProcessor) syncProcessor).start();
        firstProcessor = new PrepRequestProcessor(this, syncProcessor);
        ((PrepRequestProcessor) firstProcessor).start();
    }

    // 提交请求到处理链
    public void submitRequestNow(Request si) {
        touch(si.cnxn);
        firstProcessor.processRequest(si);
    }

}

// 解析请求
public class PrepRequestProcessor implements RequestProcessor {

    LinkedBlockingQueue<Request> submittedRequests = new LinkedBlockingQueue<Request>();

    private final ZooKeeperServer zks;

    private final RequestProcessor nextProcessor;

    public PrepRequestProcessor(ZooKeeperServer zks, RequestProcessor nextProcessor) {
        super(..., zks.getZooKeeperServerListener());
        this.nextProcessor = nextProcessor;
        this.zks = zks;
    }

    @Override
    public void processRequest(Request request) {
        submittedRequests.add(request);
    }

    @Override
    public void run() {
        while (true) {
            Request request = submittedRequests.take();
            request.prepStartTime = Time.currentElapsedTime();
            pRequest(request);
            {
                request.setHdr(null);
                request.setTxn(null);

                // 解析请求，读请求hdr为空
                pRequestHelper(request);
                {
                    switch (request.type) {
                    // 写请求，生成新的zxid
                    case OpCode.create:
                        CreateRequest create2Request = new CreateRequest();
                        pRequest2Txn(request.type, zks.getNextZxid(), request, create2Request, true);
                        {
                            request.setHdr(new TxnHeader(request.sessionId, request.cxid, zxid, ..., type));
                            switch (type) {
                            case OpCode.create:
                                pRequest2TxnCreate(type, request, record, deserialize);
                                {
                                    // 请求反序列化
                                    ByteBufferInputStream.byteBuffer2Record(request.request, record);

                                    // 其他处理逻辑
                                }
                                break;
                            }
                        }
                        break;
                    case OpCode.setData:
                        SetDataRequest setDataRequest = new SetDataRequest();
                        pRequest2Txn(request.type, zks.getNextZxid(), request, setDataRequest, true);
                        break;
                    
                    // 读请求
                    case OpCode.exists:
                    case OpCode.getData:
                    case OpCode.setWatches:
                        zks.sessionTracker.checkSession(request.sessionId, request.getOwner());
                        break;
                    }
                }

                request.zxid = zks.getZxid();
                nextProcessor.processRequest(request);
            }
        }
    }

}

// 同步log
public class SyncRequestProcessor implements RequestProcessor {

    private final BlockingQueue<Request> queuedRequests = new LinkedBlockingQueue<Request>();

    private final ZooKeeperServer zks;

    private final RequestProcessor nextProcessor;

    public SyncRequestProcessor(ZooKeeperServer zks, RequestProcessor nextProcessor) {
        super(..., zks.getZooKeeperServerListener());
        this.zks = zks;
        this.nextProcessor = nextProcessor;
        // 批次处理
        this.toFlush = new ArrayDeque<>(zks.getMaxBatchSize());
    }

    @Override
    public void processRequest(final Request request) {
        request.syncQueueStartTime = Time.currentElapsedTime();
        queuedRequests.add(request);
    }

    @Override
    public void run() {
        while (true) {
            long pollTime = Math.min(zks.getMaxWriteQueuePollTime(), getRemainingDelay());
            Request si = queuedRequests.poll(pollTime, TimeUnit.MILLISECONDS);

            res = zks.getZKDatabase().append(si);
            {
                return snapLog.append(si);
                {
                    return txnLog.append(si.getHdr(), si.getTxn(), si.getTxnDigest());
                    {
                        // 读请求
                        if (hdr == null) {
                            return false;
                        }

                        if (logStream == null) {
                            logFileWrite = new File(logDir, Util.makeLogName(hdr.getZxid()));
                            fos = new FileOutputStream(logFileWrite);
                            logStream = new BufferedOutputStream(fos);
                            oa = BinaryOutputArchive.getArchive(logStream);
                        }

                        // 写入log文件
                        byte[] buf = Util.marshallTxnEntry(hdr, txn, digest);
                        Util.writeTxnBytes(oa, buf);
                        return true;
                    }
                }
            }

            // 写操作
            if (res) {
                if (shouldSnapshot()) {
                    // roll the log
                    zks.getZKDatabase().rollLog();
                    
                    // 镜像线程
                    new ZooKeeperThread("Snapshot Thread") {
                        public void run() {
                            // take a snapshot
                            // 所有操作都是幂等的，不用担心镜像过程中dataTree发生变化
                            zks.takeSnapshot();
                            {
                                txnLogFactory.save(zkDb.getDataTree(), zkDb.getSessionWithTimeOuts(), false);
                            }
                        }
                    }.start();
                }
            } else if (toFlush.isEmpty()) {
                // optimization for read heavy workloads
                nextProcessor.processRequest(si);
                if (this.nextProcessor instanceof Flushable) {
                    ((Flushable) this.nextProcessor).flush();
                }
                continue;
            }

            toFlush.add(si);
            if (shouldFlush()) {
                flush();
                {
                    // fsync log
                    zks.getZKDatabase().commit();

                    while (!this.toFlush.isEmpty()) {
                        final Request i = this.toFlush.remove();
                        this.nextProcessor.processRequest(i);
                    }

                    if (this.nextProcessor instanceof Flushable) {
                        ((Flushable) this.nextProcessor).flush();
                    }
                }
            }
        }
    }

}

// 请求处理线程
public class FinalRequestProcessor implements RequestProcessor {

    ZooKeeperServer zks;

    public FinalRequestProcessor(ZooKeeperServer zks) {
        this.zks = zks;
    }

    public void processRequest(Request request) {
        // 处理写请求
        ProcessTxnResult rc = applyRequest(request);
        {
            return zks.processTxn(request);
            {
                TxnHeader hdr = request.getHdr();
                final boolean writeRequest = (hdr != null);
                // 集群模式
                final boolean quorumRequest = request.isQuorum();

                // 此处不处理读请求
                if (!writeRequest && !quorumRequest) {
                    return new ProcessTxnResult();
                    {
                        processTxnInDB(hdr, request.getTxn(), request.getTxnDigest());
                        {
                            if (hdr == null) {
                                // 不处理读请求
                                return new ProcessTxnResult();
                            } else {
                                // 处理写请求
                                return getZKDatabase().processTxn(hdr, txn, digest);
                            }
                        }

                        if (quorumRequest) {
                            getZKDatabase().addCommittedProposal(request);
                        }
                    }
                }


            }
        }

        ServerCnxn cnxn = request.cnxn;

        // 处理读请求
        switch (request.type) {
            case OpCode.create:
                lastOp = "CREA";
                rsp = new CreateResponse(rc.path);
                err = Code.get(rc.err);
                break;
            case OpCode.getData:
                lastOp = "GETD";
                GetDataRequest getDataRequest = new GetDataRequest();
                ByteBufferInputStream.byteBuffer2Record(request.request, getDataRequest);
                path = getDataRequest.getPath();
                rsp = handleGetDataRequest(getDataRequest, cnxn, request.authInfo);
                {
                    GetDataRequest getDataRequest = (GetDataRequest) request;
                    // 请求路径
                    String path = getDataRequest.getPath();
                    DataNode n = zks.getZKDatabase().getNode(path);
                    if (n == null) {
                        throw new KeeperException.NoNodeException();
                    }
                    zks.checkACL(cnxn, zks.getZKDatabase().aclForNode(n), ZooDefs.Perms.READ, ..., path, ...);
                    Stat stat = new Stat();
                    // 节点数据
                    byte[] b = zks.getZKDatabase().getData(path, stat, getDataRequest.getWatch() ? cnxn : null);
                    return new GetDataResponse(b, stat);
                }
                break;
        }

        ReplyHeader hdr = new ReplyHeader(request.cxid, lastZxid, err.intValue());

        // 发送响应
        if (path == null || rsp == null) {
            responseSize = cnxn.sendResponse(hdr, rsp, "response");
        } else {
            switch (opCode) {
                case OpCode.getData : {
                    GetDataResponse getDataResponse = (GetDataResponse) rsp;
                    stat = getDataResponse.getStat();
                    responseSize = cnxn.sendResponse(hdr, rsp, "response", path, stat, opCode);
                    {
                         // 序列化
                        ByteBuffer[] bb = serialize(h, r, tag, cacheKey, stat, opCode);
                        bb[0].rewind();
                        sendBuffer(bb);
                        {
                            // 插入outgoingBuffers等待workPool线程发送
                            synchronized (outgoingBuffers) {
                                for (ByteBuffer buffer : buffers) {
                                    outgoingBuffers.add(buffer);
                                }
                                outgoingBuffers.add(packetSentinel);
                            }
                        }
                    }
                    break;
                }
                case OpCode.getChildren2 : {
                    GetChildren2Response getChildren2Response = (GetChildren2Response) rsp;
                    stat = getChildren2Response.getStat();
                    responseSize = cnxn.sendResponse(hdr, rsp, "response", path, stat, opCode);
                    break;
                }
                default:
                    responseSize = cnxn.sendResponse(hdr, rsp, "response");
            }
        }
    }

}

```

# zookeeper集群

