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

public class ZooKeeperServerMain {

    public static void main(String[] args) {
        ZooKeeperServerMain main = new ZooKeeperServerMain();

        main.initializeAndRun(args);
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

---

# zookeeper集群

## 启动过程

```java

public class QuorumPeerMain {

    public static void main(String[] args) {
        QuorumPeerMain main = new QuorumPeerMain();

        main.initializeAndRun(args);
        {
            QuorumPeerConfig config = new QuorumPeerConfig();
            if (args.length == 1) {
                // 配置文件解析
                config.parse(args[0]);
            }

            if (args.length == 1 && config.isDistributed()) {
                // 集群模式
                runFromConfig(config);
                {
                    // 同单节点模式: 处理client连接
                    if (config.getClientPortAddress() != null) {
                        cnxnFactory = ServerCnxnFactory.createFactory();
                        cnxnFactory.configure(config.getClientPortAddress(), config.getMaxClientCnxns(), ...);
                    }

                    quorumPeer = new QuorumPeer();
                    // 管理snap和log
                    quorumPeer.setTxnFactory(new FileTxnSnapLog(config.getDataLogDir(), config.getDataDir()));
                    // 选举算法
                    quorumPeer.setElectionType(config.getElectionAlg());
                    // 核心参数
                    quorumPeer.setMyid(config.getServerId());
                    quorumPeer.setTickTime(config.getTickTime());
                    quorumPeer.setMinSessionTimeout(config.getMinSessionTimeout());
                    quorumPeer.setMaxSessionTimeout(config.getMaxSessionTimeout());
                    quorumPeer.setInitLimit(config.getInitLimit());
                    quorumPeer.setSyncLimit(config.getSyncLimit());
                    // 内存DataTree
                    quorumPeer.setZKDatabase(new ZKDatabase(quorumPeer.getTxnFactory()));
                    // 集群成员管理
                    quorumPeer.setQuorumVerifier(config.getQuorumVerifier(), false);
                    // 网络IO
                    quorumPeer.setCnxnFactory(cnxnFactory);

                    quorumPeer.start();
                    {
                        loadDataBase();
                        {
                            // 加载snap和log
                            zkDb.loadDataBase();
                        }

                        startServerCnxnFactory();
                        {
                            cnxnFactory.start();
                        }

                        startLeaderElection();
                        {
                            // 初始状态：投票给自己
                            if (getPeerState() == ServerState.LOOKING) {
                                currentVote = new Vote(myid, getLastLoggedZxid(), getCurrentEpoch());
                            }

                            this.electionAlg = createElectionAlgorithm(electionType);
                            {
                                QuorumCnxManager qcm = new QuorumCnxManager(this, this.getMyId(), ...);
                                {
                                    this.connectionExecutor = new ThreadPoolExecutor(3, ...);
                                    this.connectionExecutor.allowCoreThreadTimeOut(true);

                                    // 消息接收队列
                                    this.recvQueue = new CircularBlockingQueue<Message>(RECV_CAPACITY);
                                    // 消息发送队列，key为节点id
                                    this.queueSendMap = new ConcurrentHashMap<Long, BlockingQueue<ByteBuffer>>();
                                    // 消息收发线程，key为节点id
                                    this.senderWorkerMap = new ConcurrentHashMap<Long, SendWorker>();
                                    // 发送的最后一条消息，key为节点id，用于丢包时重发
                                    this.lastMessageSent = new ConcurrentHashMap<Long, ByteBuffer>();

                                    listener = new Listener();
                                }

                                QuorumCnxManager.Listener listener = qcm.listener;
                                listener.start();
                                {
                                    addresses = self.getElectionAddress().getAllAddresses();

                                    listenerHandlers = addresses.stream().map(address ->
                                                new ListenerHandler(address, self.shouldUsePortUnification(), self.isSslQuorum(), latch))
                                            .collect(Collectors.toList());

                                    // 提交listener到executor
                                    final ExecutorService executor = Executors.newFixedThreadPool(addresses.size());
                                    listenerHandlers.forEach(executor::submit);
                                }

                                FastLeaderElection fle = new FastLeaderElection(this, qcm);
                                {
                                    // 发送队列
                                    sendqueue = new LinkedBlockingQueue<ToSend>();
                                    // 接收队列
                                    recvqueue = new LinkedBlockingQueue<Notification>();
                                    this.messenger = new Messenger(manager);
                                }

                                fle.start();
                                {
                                    this.messenger.start();
                                }
                            }
                        }

                        // 启动peer线程
                        super.start();
                    }

                    quorumPeer.join();
                }
            } else {
                // there is only server in the quorum -- run as standalone
                ZooKeeperServerMain.main(args);
            }
        }
    }

}

```

## 选举连接

![leader-election](/assets/images/2023-04-03/leader-election.png)

所有集群成员之间两两建立长连接

```java

class ListenerHandler implements Runnable {

    ListenerHandler(InetSocketAddress address, ...) {
        this.address = address;
    }

    @Override
    public void run() {
        acceptConnections();
        {
            serverSocket = createNewServerSocket();

            while (!shutdown) {
                sock = serverSocket.accept();

                sock.setTcpNoDelay(true);
                sock.setKeepAlive(tcpKeepAlive);
                sock.setSoTimeout(this.socketTimeout);

                receiveConnection(sock);
                {
                    DataInputStream din = new DataInputStream(new BufferedInputStream(sock.getInputStream()));
                    handleConnection(sock, din);
                    {
                        // tcp自身就是双向链接，sid较大者主动连接
                        if (sid < self.getMyId()) {
                            SendWorker sw = senderWorkerMap.get(sid);
                            if (sw != null) {
                                sw.finish();
                            }

                            closeSocket(sock);

                            connectOne(sid, electionAddr);
                            {
                                initiateConnection(electionAddr, sid);
                                {
                                    Socket sock = SOCKET_FACTORY.get();
                                    sock.connect(electionAddr.getReachableOrOne(), cnxTO);

                                    startConnection(sock, sid);
                                    {
                                        // 发送我们的选举地址
                                        BufferedOutputStream buf = new BufferedOutputStream(sock.getOutputStream());
                                        DataOutputStream dout = new DataOutputStream(buf);
                                        dout.writeLong(protocolVersion);
                                        dout.writeLong(self.getMyId());
                                        String addr = addressesToSend.stream().collect(Collectors.joining("|"));
                                        byte[] addr_bytes = addr.getBytes();
                                        dout.writeInt(addr_bytes.length);
                                        dout.write(addr_bytes);
                                        dout.flush();

                                        
                                        // 建立数据收发通道
                                        DataInputStream din = new DataInputStream(new BufferedInputStream(sock.getInputStream()));

                                        SendWorker sw = new SendWorker(sock, sid);
                                        RecvWorker rw = new RecvWorker(sock, din, sid, sw);
                                        sw.setRecv(rw);

                                        senderWorkerMap.put(sid, sw);
                                        
                                        // 发送队列
                                        queueSendMap.putIfAbsent(sid, new CircularBlockingQueue<>(SEND_CAPACITY));

                                        sw.start();
                                        rw.start();
                                    }
                                }
                            }
                        } else if (sid == self.getMyId()) {
                            // we saw this case in ZOOKEEPER-2164
                        } else { // Otherwise start worker threads to receive data.
                            // 建立数据收发通道
                            // 发送queueSendMap队列中的消息
                            SendWorker sw = new SendWorker(sock, sid);
                            // 接收消息放到recvQueue
                            RecvWorker rw = new RecvWorker(sock, din, sid, sw);
                            sw.setRecv(rw);

                            senderWorkerMap.put(sid, sw);
                            
                            // 发送队列
                            queueSendMap.putIfAbsent(sid, new CircularBlockingQueue<>(SEND_CAPACITY));

                            sw.start();
                            rw.start();
                        }
                    }
                }
            }
        }
    }

}

class Messenger {

    Messenger(QuorumCnxManager manager) {
        // 把sendqueue中的消息插入queueSendMap中的队列
        this.ws = new WorkerSender(manager);
        this.wsThread = new Thread(this.ws, "WorkerSender[myid=" + self.getMyId() + "]");
        this.wsThread.setDaemon(true);

        // 选举阶段从recvQueue接收消息放入队列recvqueue
        this.wr = new WorkerReceiver(manager);
        this.wrThread = new Thread(this.wr, "WorkerReceiver[myid=" + self.getMyId() + "]");
        this.wrThread.setDaemon(true);
    }

    void start() {
        this.wsThread.start();
        this.wrThread.start();
        {
            while (!stop) {
                response = manager.pollRecvQueue(3000, TimeUnit.MILLISECONDS);
                if (response == null) {
                    continue;
                }

                int rstate = response.buffer.getInt();
                long rleader = response.buffer.getLong();
                long rzxid = response.buffer.getLong();
                long relectionEpoch = response.buffer.getLong();

                if (self.getPeerState() == QuorumPeer.ServerState.LOOKING) {
                    // 插入接收队列
                    recvqueue.offer(n);

                    // 通知发送方更新logicalclock
                    if ((ackstate == QuorumPeer.ServerState.LOOKING)
                        && (n.electionEpoch < logicalclock.get())) {
                        Vote v = getVote();
                        QuorumVerifier qv = self.getQuorumVerifier();
                        ToSend notmsg = new ToSend(ToSend.mType.notification, v.getId(), ...);
                        sendqueue.offer(notmsg);
                    }
                } else {
                    // 通知对方我们的leader
                    Vote current = self.getCurrentVote();
                    if (ackstate == QuorumPeer.ServerState.LOOKING) {
                        QuorumVerifier qv = self.getQuorumVerifier();
                        ToSend notmsg = new ToSend(ToSend.mType.notification, current.getId(), ...);
                        sendqueue.offer(notmsg);
                    }
                }
            }
        }
    }

}

```

## 选举算法

```java

public class QuorumPeer {

    @Override
    public void run() {
        
        // 状态决定行为
        while (running) {
            
            switch (getPeerState()) {
            case LOOKING:

                // leader选举
                setCurrentVote(makeLEStrategy().lookForLeader());

                break;
            case OBSERVING:
                
                // 创建ObserverZooKeeperServer
                setObserver(makeObserver(logFactory));
                observer.observeLeader();
            
                break;
            case FOLLOWING:
                
                // 创建FollowerZooKeeperServer
                setFollower(makeFollower(logFactory));
                follower.followLeader();
                
                break;
            case LEADING:
                
                // 创建LeaderZooKeeperServer
                setLeader(makeLeader(logFactory));
                // #peer#3.4 leader.lead()
                leader.lead();

                setLeader(null);

                break;
            }
        }

    }

}

// leader选举
public Vote lookForLeader() {

    Map<Long, Vote> recvset = new HashMap<Long, Vote>();

    // 收到非LOOKING状态且logicalclock更大的通知
    Map<Long, Vote> outofelection = new HashMap<Long, Vote>();


    // 选举自己
    synchronized (this) {
        logicalclock.incrementAndGet();
        updateProposal(getInitId(), getInitLastLoggedZxid(), getPeerEpoch());
    }

    // 通知所有投票者
    sendNotifications();
    {
        for (long sid : self.getCurrentAndNextConfigVoters()) {
            QuorumVerifier qv = self.getQuorumVerifier();
            ToSend notmsg = new ToSend(..., proposedLeader, proposedZxid, ...);
            sendqueue.offer(notmsg);    
        }
    }

    while (self.getPeerState() == ServerState.LOOKING) {
        Notification n = recvqueue.poll(notTimeout, ...);

        if (n == null) {
            if (manager.haveDelivered()) {
                // 消息已发送但没收到通知则重复通知
                sendNotifications();
            } else {
                // 重新建立连接
                manager.connectAll();
            }

            continue;
        }

        if (validVoter(n.sid) && validVoter(n.leader)) {
            switch (n.state) {
                case LOOKING:
                    // If notification > current, replace and send messages out
                    if (n.electionEpoch > logicalclock.get()) {
                        logicalclock.set(n.electionEpoch);
                        recvset.clear();

                        // 收到更高投票则更新proposal并群发通知
                        // order by epoch, zxid, sid
                        if (totalOrderPredicate(n.leader, n.zxid, n.peerEpoch, getInitId(), getInitLastLoggedZxid(), getPeerEpoch())) {
                            updateProposal(n.leader, n.zxid, n.peerEpoch);
                        } else {
                            updateProposal(getInitId(), getInitLastLoggedZxid(), getPeerEpoch());
                        }
                        sendNotifications();
                    } else if (n.electionEpoch < logicalclock.get()) {
                        break;
                    } else if (totalOrderPredicate(n.leader, n.zxid, n.peerEpoch, proposedLeader, proposedZxid, proposedEpoch)) {
                        // 收到更高投票则更新proposal并群发通知
                        updateProposal(n.leader, n.zxid, n.peerEpoch);
                        sendNotifications();
                    }

                    // don't care about the version if it's in LOOKING state
                    recvset.put(n.sid, new Vote(n.leader, n.zxid, n.electionEpoch, n.peerEpoch));

                    voteSet = getVoteTracker(recvset, new Vote(proposedLeader, proposedZxid, logicalclock.get(), proposedEpoch));
                    {
                        // 收集所有跟我的proposal一样的vote
                        for (Map.Entry<Long, Vote> entry : votes.entrySet()) {
                            if (vote.equals(entry.getValue())) {
                                voteSet.addAck(entry.getKey());
                            }
                        }

                        return voteSet;
                    }

                    // 超过半数投票跟我的proposal一样
                    if (voteSet.hasAllQuorums()) {
                        
                        // 等待200ms观察是否有延迟的更高的vote
                        // Verify if there is any change in the proposed leader
                        while ((n = recvqueue.poll(finalizeWait, ...)) != null) {
                            if (totalOrderPredicate(n.leader, n.zxid, n.peerEpoch, proposedLeader, proposedZxid, proposedEpoch)) {
                                recvqueue.put(n);
                                break;
                            }
                        }

                        /*
                        * This predicate is true once we don't read any new
                        * relevant message from the reception queue
                        */
                        if (n == null) {
                            // leader确定
                            setPeerState(proposedLeader, voteSet);
                            Vote endVote = new Vote(proposedLeader, proposedZxid, logicalclock.get(), proposedEpoch);
                            recvqueue.clear();
                            return endVote;
                        }
                    }
                    break;

                case OBSERVING:
                    break;

                case FOLLOWING:
                    // 判断此follower的leader的是否合法
                    Vote resultFN = receivedFollowingNotification(recvset, outofelection, voteSet, n);
                    {
                        Vote vote = new Vote(n.leader, n.zxid, n.electionEpoch, n.peerEpoch, n.state);
                        /*
                        * Consider all notifications from the same epoch together.
                        */
                        if (n.electionEpoch == logicalclock.get()) {
                            recvset.put(n.sid, vote);
                            voteSet = getVoteTracker(recvset, vote);
                            if (voteSet.hasAllQuorums() && checkLeader(recvset, n.leader, n.electionEpoch)) {
                                setPeerState(n.leader, voteSet);
                                Vote endVote = new Vote(n.leader, n.zxid, n.electionEpoch, n.peerEpoch);
                                leaveInstance(endVote);
                                return endVote;
                            }
                        }

                        /*
                        * Before joining an established ensemble, verify that
                        * a majority are following the same leader.
                        */
                        outofelection.put(n.sid, vote);
                        voteSet = getVoteTracker(outofelection, vote);
                        if (voteSet.hasAllQuorums() && checkLeader(outofelection, n.leader, n.electionEpoch)) {
                            synchronized (this) {
                                logicalclock.set(n.electionEpoch);
                                setPeerState(n.leader, voteSet);
                            }
                            Vote endVote = new Vote(n.leader, n.zxid, n.electionEpoch, n.peerEpoch);
                            leaveInstance(endVote);
                            return endVote;
                        }

                        return null;
                    }

                    if (resultFN == null) {
                        break;
                    } else {
                        return resultFN;
                    }

                case LEADING:
                    Vote resultLN = receivedLeadingNotification(recvset, outofelection, voteSet, n);
                    {
                        return receivedFollowingNotification(recvset, outofelection, voteSet, n);
                    }

                    if (resultLN == null) {
                        break;
                    } else {
                        return resultLN;
                    }
            }
        }
    }

}

```

## log复制

### leader

```java

// 处理客户端请求
public class LeaderZooKeeperServer extends QuorumZooKeeperServer {

    // 跟单节点zk比主要是替换了处理链
    @Override
    protected void setupRequestProcessors() {
        RequestProcessor finalProcessor = new FinalRequestProcessor(this);
        RequestProcessor toBeAppliedProcessor = new Leader.ToBeAppliedRequestProcessor(finalProcessor, getLeader());
        commitProcessor = new CommitProcessor(toBeAppliedProcessor, ...);
        commitProcessor.start();
        // 发送proposal，等待收到超过半数ack则commit
        ProposalRequestProcessor proposalProcessor = new ProposalRequestProcessor(this, commitProcessor);
        proposalProcessor.initialize();
        prepRequestProcessor = new PrepRequestProcessor(this, proposalProcessor);
        prepRequestProcessor.start();
        firstProcessor = new LeaderRequestProcessor(this, prepRequestProcessor);
    }

}

public class Leader extends LearnerMaster {

    private final List<ServerSocket> serverSockets = new LinkedList<>();

    public Leader(QuorumPeer self, LeaderZooKeeperServer zk) {
        this.self = self;
        this.zk = zk;

        addresses = self.getQuorumAddress().getAllAddresses();

        // 监听集群通信端口
        addresses.stream()
          .map(address -> createServerSocket(address, ...))
          .filter(Optional::isPresent)
          .map(Optional::get)
          .forEach(serverSockets::add);
    }

    void lead() {

        zk.loadData();

        cnxAcceptor = new LearnerCnxAcceptor();
        cnxAcceptor.start();
        {

            ExecutorService executor = Executors.newFixedThreadPool(serverSockets.size());
            serverSockets.forEach(serverSocket ->
                        executor.submit(new LearnerCnxAcceptorHandler(serverSocket, latch)));
                        {
                            while (!stop.get()) {
                                acceptConnections();
                                {
                                    socket = serverSocket.accept();
                                    socket.setSoTimeout(self.tickTime * self.initLimit);
                                    BufferedInputStream is = new BufferedInputStream(socket.getInputStream());
                                    // 每个线程处理一个连接
                                    LearnerHandler fh = new LearnerHandler(socket, is, Leader.this);
                                    fh.start();
                                }
                            }
                        }
        }

        long epoch = getEpochToPropose(self.getMyId(), self.getAcceptedEpoch());
        zk.setZxid(ZxidUtils.makeZxid(epoch, 0));

        newLeaderProposal.packet = new QuorumPacket(NEWLEADER, zk.getZxid(), null, null);
        newLeaderProposal.addQuorumVerifier(self.getQuorumVerifier());

        // 等待收到超过半数的follower的连接
        waitForEpochAck(self.getMyId(), leaderStateSummary);
        {
            synchronized (electingFollowers) {
                electingFollowers.add(id);

                QuorumVerifier verifier = self.getQuorumVerifier();
                if (electingFollowers.contains(self.getMyId()) && verifier.containsQuorum(electingFollowers)) {
                    electionFinished = true;
                    electingFollowers.notifyAll();
                } else {
                    long cur = start;
                    long end = start + self.getInitLimit() * self.getTickTime();
                    while (!electionFinished && cur < end) {
                        electingFollowers.wait(end - cur);
                    }
                    if (!electionFinished) {
                        throw new InterruptedException("Timeout while waiting for epoch to be acked by quorum");
                    }
                }
            }
        }

        // 等待NEWLEADER命令收到超过半数的响应
        waitForNewLeaderAck(self.getMyId(), zk.getZxid());
        {
            synchronized (newLeaderProposal.qvAcksetPairs) {

                newLeaderProposal.addAck(sid);

                if (newLeaderProposal.hasAllQuorums()) {
                    quorumFormed = true;
                    newLeaderProposal.qvAcksetPairs.notifyAll();
                } else {
                    long cur = start;
                    long end = start + self.getInitLimit() * self.getTickTime();
                    while (!quorumFormed && cur < end) {
                        newLeaderProposal.qvAcksetPairs.wait(end - cur);
                    }
                    if (!quorumFormed) {
                        throw new InterruptedException("Timeout while waiting for NEWLEADER to be acked by quorum");
                    }
                }
            }
        }

        // 开始处理client请求
        startZkServer();

        boolean tickSkip = true;

        while (true) {
            // 定时tick
            long cur = start;
            long end = start + self.tickTime / 2;
            while (cur < end) {
                wait(end - cur);
            }

            SyncedLearnerTracker syncedAckSet = new SyncedLearnerTracker();
            syncedAckSet.addQuorumVerifier(self.getQuorumVerifier());

            syncedAckSet.addAck(self.getMyId());
            for (LearnerHandler f : getLearners()) {
                if (f.synced()) {
                    syncedAckSet.addAck(f.getSid());
                }
            }

            // 心跳响应不过半
            if (!tickSkip && !syncedAckSet.hasAllQuorums()) {
                break;
            }

            // 隔次检查
            tickSkip = !tickSkip;

            // 定时发送心跳
            for (LearnerHandler f : getLearners()) {
                f.ping();
            }
        }
    }

}

// 处理follower连接的线程
public class LearnerHandler {

    LearnerHandler(Socket sock, ...) {
        this.sock = sock;
    }

    @Override
    public void run() {
        learnerMaster.addLearnerHandler(this);

        ia = BinaryInputArchive.getArchive(bufferedInput);
        oa = BinaryOutputArchive.getArchive(new BufferedOutputStream(sock.getOutputStream()));

        // 等待接收FOLLOWERINFO
        QuorumPacket qp = new QuorumPacket();
        ia.readRecord(qp, "packet");

        // 发送LEADERINFO
        QuorumPacket newEpochPacket = new QuorumPacket(Leader.LEADERINFO, newLeaderZxid, ver, null);
        oa.writeRecord(newEpochPacket, "packet");
        
        // 等待接收ACKEPOCH
        QuorumPacket ackEpochPacket = new QuorumPacket();
        ia.readRecord(ackEpochPacket, "packet");
        ss = new StateSummary(bbepoch.getInt(), ackEpochPacket.getZxid());
        learnerMaster.waitForEpochAck(this.getSid(), ss);

        boolean needSnap = syncFollower(peerLastZxid, learnerMaster);
        if (needSnap) {
            // 发送镜像给follower
            long zxidToSend = learnerMaster.getZKDatabase().getDataTreeLastProcessedZxid();
            oa.writeRecord(new QuorumPacket(Leader.SNAP, zxidToSend, null, null), "packet");
            learnerMaster.getZKDatabase().serializeSnapshot(oa);
            oa.writeString("BenWasHere", "signature");        
        }

        QuorumPacket newLeaderQP = new QuorumPacket(Leader.NEWLEADER, newLeaderZxid, ...);
        queuedPackets.add(newLeaderQP);

        // 发送packet给follower
        startSendingPackets();
        {
            new Thread() {
                public void run() {
                    sendPackets();
                    {
                        while (true) {
                            QuorumPacket p = queuedPackets.poll();
                            oa.writeRecord(p, "packet");
                        }
                    }
                }
            }.start();
        }

        // 等待ACK
        qp = new QuorumPacket();
        ia.readRecord(qp, "packet");

        // 发送UPTODATE标识数据同步完毕
        queuedPackets.add(new QuorumPacket(Leader.UPTODATE, -1, null, null));

        // 处理follower的命令
        while (true) {
            qp = new QuorumPacket();
            ia.readRecord(qp, "packet");

            switch (qp.getType()) {
            case Leader.ACK:
                // 处理proposal的ack，超过半数则commit
                learnerMaster.processAck(this.sid, qp.getZxid(), sock.getLocalSocketAddress());
                {
                    Proposal p = outstandingProposals.get(zxid);
                    // 收集ack
                    p.addAck(sid);

                    tryToCommit(p, zxid, followerAddr);
                    {
                        // make sure that ops are committed in order.
                        if (outstandingProposals.containsKey(zxid - 1)) {
                            return false;
                        }

                        if (!p.hasAllQuorums()) {
                            return false;
                        }

                        outstandingProposals.remove(zxid);

                        if (p.request != null) {
                            toBeApplied.add(p);
                        }

                        // 超过半数则提交
                        commit(zxid);
                        {
                            QuorumPacket qp = new QuorumPacket(Leader.COMMIT, zxid, null, null);
                            sendPacket(qp);
                            {
                                synchronized (forwardingFollowers) {
                                    for (LearnerHandler f : forwardingFollowers) {
                                        f.queuePacket(qp);
                                    }
                                }
                            }
                        }

                        zk.commitProcessor.commit(p.request);
                    }
                }

                break;
            case Leader.PING:
                // Process the touches
                ByteArrayInputStream bis = new ByteArrayInputStream(qp.getData());
                DataInputStream dis = new DataInputStream(bis);
                while (dis.available() > 0) {
                    long sess = dis.readLong();
                    int to = dis.readInt();
                    learnerMaster.touch(sess, to);
                }
                break;
            case Leader.REQUEST:
                bb = ByteBuffer.wrap(qp.getData());
                sessionId = bb.getLong();
                cxid = bb.getInt();
                type = bb.getInt();
                bb = bb.slice();
                Request si;
                if (type == OpCode.sync) {
                    si = new LearnerSyncRequest(this, sessionId, cxid, type, bb, qp.getAuthinfo());
                } else {
                    si = new Request(null, sessionId, cxid, type, bb, qp.getAuthinfo());
                }
                si.setOwner(this);
                learnerMaster.submitLearnerRequest(si);
                break;
            }
        }
    }

}


```

### follower

```java

public class FollowerZooKeeperServer extends LearnerZooKeeperServer {

    // 跟单节点zk比主要是替换了处理链
    @Override
    protected void setupRequestProcessors() {
        RequestProcessor finalProcessor = new FinalRequestProcessor(this);
        commitProcessor = new CommitProcessor(finalProcessor, ...);
        commitProcessor.start();
        firstProcessor = new FollowerRequestProcessor(this, commitProcessor);
        ((FollowerRequestProcessor) firstProcessor).start();
        syncProcessor = new SyncRequestProcessor(this, new SendAckRequestProcessor(getFollower()));
        syncProcessor.start();
    }

}

public class Follower extends Learner {

     Follower(final QuorumPeer self, final FollowerZooKeeperServer zk) {
        this.self = self;
        this.fzk = zk;
        this.zk = zk;
    }

    void followLeader() {
        // 根据当前的投票确定leader
        QuorumServer leaderServer = findLeader();

        connectToLeader(leaderServer.addr, leaderServer.hostname);
        {
            ExecutorService executor = Executors.newFixedThreadPool(addresses.size());
            AtomicReference<Socket> socket = new AtomicReference<>(null);
            addresses.stream().map(address -> new LeaderConnector(address, socket, latch)).forEach(executor::submit);
            {
                Socket sock = new Socket();

                // 重试5次直到超时
                for (int tries = 0; tries < 5 && socket.get() == null; tries++) {
                    remainingTimeout = connectTimeout - (int) ((nanoTime() - startNanoTime) / 1_000_000);
                    if (remainingTimeout <= 0) {
                        throw new IOException("connectToLeader exceeded on retries.");
                    }

                    sock.connect(address, Math.min(connectTimeout, remainingTimeout));
                    break;
                }

                socket.compareAndSet(null, sock);
            }

            sock = socket.get();

            // 收发通道
            leaderIs = BinaryInputArchive.getArchive(new BufferedInputStream(sock.getInputStream()));
            leaderOs = BinaryOutputArchive.getArchive(new BufferedOutputStream(sock.getOutputStream()));
        }

        long newEpochZxid = registerWithLeader(Leader.FOLLOWERINFO);
        {
            QuorumPacket qp = new QuorumPacket();
            qp.setType(pktType);
            qp.setZxid(ZxidUtils.makeZxid(self.getAcceptedEpoch(), 0));

            LearnerInfo li = new LearnerInfo(self.getMyId(), 0x10000, self.getQuorumVerifier().getVersion());
            boa.writeRecord(li, "LearnerInfo");
            qp.setData(bsid.toByteArray());

            // 向leader发送FOLLOWERINFO
            writePacket(qp, true);
            // 等待leader响应
            readPacket(qp);

            final long newEpoch = ZxidUtils.getEpochFromZxid(qp.getZxid());
            if (qp.getType() == Leader.LEADERINFO) {
                // 向leader发送ACKEPOCH
                QuorumPacket ackNewEpoch = new QuorumPacket(Leader.ACKEPOCH, lastLoggedZxid, epochBytes, null);
                writePacket(ackNewEpoch, true);
                return ZxidUtils.makeZxid(newEpoch, 0);
            }
        }

        syncWithLeader(newEpochZxid);
        {
            // 读取log差异信息
            QuorumPacket qp = new QuorumPacket();
            readPacket(qp);

            // log有差异
            if (qp.getType() == Leader.DIFF) {
                self.setSyncMode(QuorumPeer.SyncMode.DIFF);
                if (zk.shouldForceWriteInitialSnapshotAfterLeaderElection()) {
                    snapshotNeeded = true;
                    syncSnapshot = true;
                } else {
                    snapshotNeeded = false;
                }
            } else if (qp.getType() == Leader.SNAP) {
                // 需要解析leader发送的snap
                self.setSyncMode(QuorumPeer.SyncMode.SNAP);
                zk.getZKDatabase().deserializeSnapshot(leaderIs);
                zk.getZKDatabase().setlastProcessedZxid(qp.getZxid());
                // immediately persist the latest snapshot when there is txn log gap
                syncSnapshot = true;
            } else if (qp.getType() == Leader.TRUNC) {
                // trunc到leader指定的位置
                //we need to truncate the log to the lastzxid of the leader
                self.setSyncMode(QuorumPeer.SyncMode.TRUNC);
                boolean truncated = zk.getZKDatabase().truncateLog(qp.getZxid());
                if (!truncated) {
                    ServiceUtils.requestSystemExit(ExitCode.QUORUM_PACKET_ERROR.getValue());
                }
                zk.getZKDatabase().setlastProcessedZxid(qp.getZxid());
            } else {
                ServiceUtils.requestSystemExit(ExitCode.QUORUM_PACKET_ERROR.getValue());
            }

            zk.getZKDatabase().initConfigInZKDatabase(self.getQuorumVerifier());
            zk.createSessionTracker();

            outerLoop:
            while (self.isRunning()) {
                readPacket(qp);

                // Leader.DIFF模式需要接收有差异的proposal
                switch (qp.getType()) {
                case Leader.PROPOSAL:
                    PacketInFlight pif = new PacketInFlight();
                    logEntry = SerializeUtils.deserializeTxn(qp.getData());
                    pif.hdr = logEntry.getHeader();
                    pif.rec = logEntry.getTxn();
                    pif.digest = logEntry.getDigest();
                    // 接收proposal
                    packetsNotCommitted.add(pif);
                    break;
                
                case Leader.COMMIT:
                    pif = packetsNotCommitted.peekFirst();
                    // commit proposal
                    zk.processTxn(pif.hdr, pif.rec);
                    packetsNotCommitted.remove();
                    break;
                
                // log同步完毕退出循环
                case Leader.UPTODATE:
                    self.setZooKeeperServer(zk);
                    break outerLoop;
                
                case Leader.NEWLEADER: // Getting NEWLEADER here instead of in discovery
                    if (snapshotNeeded) {
                        zk.takeSnapshot(syncSnapshot);
                    }

                    self.setCurrentEpoch(newEpoch);
                    writeToTxnLog = true;

                    // ZOOKEEPER-3911: make sure sync the uncommitted logs before commit them (ACK NEWLEADER).
                    sock.setSoTimeout(self.tickTime * self.syncLimit);
                    self.setSyncMode(QuorumPeer.SyncMode.NONE);

                    // 启动zk
                    zk.startupWithoutServing();

                    if (zk instanceof FollowerZooKeeperServer) {
                        FollowerZooKeeperServer fzk = (FollowerZooKeeperServer) zk;
                        for (PacketInFlight p : packetsNotCommitted) {
                            // 把未commit的log写入log文件
                            fzk.logRequest(p.hdr, p.rec, p.digest);
                        }
                        packetsNotCommitted.clear();
                    }

                    // 收到NEWLEADER发送ACK
                    writePacket(new QuorumPacket(Leader.ACK, newLeaderZxid, null, null), true);
                    break;
                }
            }

            // 发送ack
            QuorumPacket ack = new QuorumPacket(Leader.ACK, 0, null, null);
            ack.setZxid(ZxidUtils.makeZxid(newEpoch, 0));

            writePacket(ack, true);
            // 开始处理client连接
            zk.startServing();

            // We need to log the stuff that came in between the snapshot and the uptodate
            if (zk instanceof FollowerZooKeeperServer) {
                FollowerZooKeeperServer fzk = (FollowerZooKeeperServer) zk;
                for (PacketInFlight p : packetsNotCommitted) {
                    fzk.logRequest(p.hdr, p.rec, p.digest);
                }
                for (Long zxid : packetsCommitted) {
                    fzk.commit(zxid);
                }
            }
        }

        // 缓存未commit的请求
        LinkedBlockingQueue<Request> pendingTxns = new LinkedBlockingQueue<Request>();

        // 处理leader指令
        QuorumPacket qp = new QuorumPacket();
        while (this.isRunning()) {
            readPacket(qp);
            processPacket(qp);
            {
                switch (qp.getType()) {
                case Leader.PING:
                    ping(qp);
                    break;
                
                case Leader.PROPOSAL:
                    TxnLogEntry logEntry = SerializeUtils.deserializeTxn(qp.getData());
                    TxnHeader hdr = logEntry.getHeader();
                    Record txn = logEntry.getTxn();
                    TxnDigest digest = logEntry.getDigest();
                    
                    fzk.logRequest(hdr, txn, digest);
                    {
                        Request request = new Request(hdr.getClientId(), hdr.getCxid(), hdr.getType(), hdr, txn, hdr.getZxid());
                        pendingTxns.add(request);
                        // 写入log文件，参靠上文单节点zk
                        syncProcessor.processRequest(request);
                    }
                    break;
                
                case Leader.COMMIT:
                    fzk.commit(qp.getZxid());
                    {
                        long firstElementZxid = pendingTxns.element().zxid;
                        if (firstElementZxid != zxid) {
                            ServiceUtils.requestSystemExit(ExitCode.UNMATCHED_TXN_COMMIT.getValue());
                        }
                        Request request = pendingTxns.remove();
                        // 应用到状态机，参靠上文单节点zk
                        commitProcessor.commit(request);
                    }
                    break;

                case Leader.COMMITANDACTIVATE:
                    // 集群成员变更
                    break;
                case Leader.SYNC:
                    fzk.sync();
                    break;
                }
            }
        }
    }

}

```

