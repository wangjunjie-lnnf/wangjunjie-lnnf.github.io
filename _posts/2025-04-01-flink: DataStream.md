---
layout: post
title:  flink-DataStream
date:   2025-04-01 22:49:07 +0000
categories: bigdata
tags: bigdata,flink
---

# flink: DataStream

flink版本为`1.19.1`

## demo

以`flink-examples`模块的`WordCount`为例，一个应用首先从`StreamExecutionEnvironment`构建`source`开始，
然后经过各种自定义函数的转换，最后以`sink`结束。如果类比可执行文件，`source`就是输入，`sink`就是输出。

```java

public class WordCount {

    public static void main(String[] args) throws Exception {
        final CLI params = CLI.fromArgs(args);

        // Create the execution environment. This is the main entrypoint to building a Flink application.
        final StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();

        // By setting the runtime mode to AUTOMATIC, Flink will choose BATCH if all sources
        // are bounded and otherwise STREAMING.
        env.setRuntimeMode(params.getExecutionMode());

        // This optional step makes the input parameters available in the Flink UI.
        env.getConfig().setGlobalJobParameters(params);

        DataStream<String> text = env.fromData(WordCountData.WORDS).name("in-memory-input");

        DataStream<Tuple2<String, Integer>> counts =
                text.flatMap(new Tokenizer())
                        .name("tokenizer")
                        .keyBy(value -> value.f0)
                        .sum(1)
                        .name("counter");

        counts.print().name("print-sink");

        // Apache Flink applications are composed lazily. 
        // Calling execute submits the Job and begins processing.
        env.execute("WordCount");
    }

    public static final class Tokenizer
            implements FlatMapFunction<String, Tuple2<String, Integer>> {

        @Override
        public void flatMap(String value, Collector<Tuple2<String, Integer>> out) {
            // normalize and split the line
            String[] tokens = value.toLowerCase().split("\\W+");

            // emit the pairs
            for (String token : tokens) {
                if (token.length() > 0) {
                    out.collect(new Tuple2<>(token, 1));
                }
            }
        }
    }
}

```

## StreamExecutionEnvironment

```java

public class StreamExecutionEnvironment {

    protected final Configuration configuration;

    /** The execution configuration for this environment. */
    protected final ExecutionConfig config;

    /** Settings that control the checkpointing behavior. */
    protected final CheckpointConfig checkpointCfg;

    protected final List<Transformation<?>> transformations = new ArrayList<>();

    public StreamExecutionEnvironment registerSlotSharingGroup(SlotSharingGroup slotSharingGroup) {
        slotSharingGroupResources.put(slotSharingGroup.getName(), ...);
        return this;
    }

    // 根据集合生成source
    public <OUT> DataStreamSource<OUT> fromData(
            Collection<OUT> data, TypeInformation<OUT> typeInfo) {

        FromElementsGeneratorFunction<OUT> generatorFunction =
                new FromElementsGeneratorFunction<>(typeInfo, getConfig(), data);

        DataGeneratorSource<OUT> generatorSource =
                new DataGeneratorSource<>(generatorFunction, data.size(), typeInfo);

        return fromSource(generatorSource, ...).setParallelism(1);
    }

    // 数字序列
    public DataStreamSource<Long> fromSequence(long from, long to) {
        return fromSource(new NumberSequenceSource(from, to), WatermarkStrategy.noWatermarks(), ...);
    }

    // Source代替之前的SourceFunction
    public <OUT> DataStreamSource<OUT> fromSource(
            Source<OUT, ?, ?> source,
            WatermarkStrategy<OUT> timestampsAndWatermarks,
            String sourceName,
            TypeInformation<OUT> typeInfo) {

        return new DataStreamSource<>(
                this,
                checkNotNull(source, "source"),
                checkNotNull(timestampsAndWatermarks, "timestampsAndWatermarks"),
                checkNotNull(resolvedTypeInfo),
                checkNotNull(sourceName));
    }

    // 直接添加transformation
    public void addOperator(Transformation<?> transformation) {
        transformations.add(transformation);
    }

    // 执行应用
    public JobExecutionResult execute(String jobName) throws Exception {       
        StreamGraph streamGraph = getStreamGraph();
        streamGraph.setJobName(jobName);

        JobClient jobClient = executeAsync(streamGraph)
        return jobClient.getJobExecutionResult().get();
    }

    public JobClient executeAsync(StreamGraph streamGraph) throws Exception {
        final PipelineExecutor executor = getPipelineExecutor();

        // 从StreamGraph生成JobGraph并提交
        CompletableFuture<JobClient> jobClientFuture =
                executor.execute(streamGraph, configuration, userClassloader);

        return jobClientFuture.get();      
    }

    // 根据transformations生成StreamGraph
    public StreamGraph getStreamGraph() {
        return new StreamGraphGenerator(new ArrayList<>(transformations), config, checkpointCfg, configuration)
                .setStateBackend(defaultStateBackend)
                .setTimeCharacteristic(getStreamTimeCharacteristic())
                .setSlotSharingGroupResource(slotSharingGroupResources)
                .generate();
    }

}

```


## Source

```java

public interface Source<T, SplitT extends SourceSplit, EnumChkT>
        extends SourceReaderFactory<T, SplitT> {

    Boundedness getBoundedness();

    // 从分配的split中读取数据
    SourceReader<T, SplitT> createReader(SourceReaderContext readerContext);

    // 管理split的分配
    SplitEnumerator<SplitT, EnumChkT> createEnumerator(SplitEnumeratorContext<SplitT> enumContext);

    // 从checkpoint恢复
    SplitEnumerator<SplitT, EnumChkT> restoreEnumerator(
            SplitEnumeratorContext<SplitT> enumContext, EnumChkT checkpoint);
}


// 用于SplitEnumerator和运行环境交互
public interface SplitEnumeratorContext<SplitT extends SourceSplit> {

    void sendEventToSourceReader(int subtaskId, SourceEvent event);

    int currentParallelism();

    Map<Integer, ReaderInfo> registeredReaders();

    void assignSplits(SplitsAssignment<SplitT> newSplitAssignments);

    void signalNoMoreSplits(int subtask);

    void callAsync(Callable<T> callable, BiConsumer<T, Throwable> handler,
            long initialDelayMillis, long periodMillis)

}

public interface SplitEnumerator<SplitT extends SourceSplit, CheckpointT>
        extends AutoCloseable, CheckpointListener {

    void start();

    // 分配split给reader
    void handleSplitRequest(int subtaskId, ...);

    // reader失败后重新添加未处理的split
    void addSplitsBack(List<SplitT> splits, int subtaskId);

    // 注册reader
    void addReader(int subtaskId);

}


// 用于SourceReader和运行环境交互
public interface SourceReaderContext {

    int getIndexOfSubtask();

    void sendSplitRequest();

    void sendSourceEventToCoordinator(SourceEvent sourceEvent);

}

public interface SourceReader<T, SplitT extends SourceSplit>
        extends AutoCloseable, CheckpointListener {

    void start();

    // 从split中读取数据发往下游
    InputStatus pollNext(ReaderOutput<T> output);

    // 收到分配的split
    void addSplits(List<SplitT> splits);

    void notifyNoMoreSplits();

    void handleSourceEvents(SourceEvent sourceEvent);

}

```

交互流程如下：

![source](/assets/images/2025-04-01/source.png)


## DataStream

DataStream的子类层次结构图下：

![DataStreamClass](/assets/images/2025-04-01/DataStreamClass.png)


核心转换api

```java

// 通用api: sink，数据分发模式，map/filter/project
public class DataStream<T> {

    protected final StreamExecutionEnvironment environment;

    protected final Transformation<T> transformation;


    public final DataStream<T> union(DataStream<T>... streams) {
        List<Transformation<T>> unionedTransforms = new ArrayList<>();
        unionedTransforms.add(this.transformation);

        for (DataStream<T> newStream : streams) {
            unionedTransforms.add(newStream.getTransformation());
        }

        return new DataStream<>(this.environment, new UnionTransformation<>(unionedTransforms));
    }

    public <R> ConnectedStreams<T, R> connect(DataStream<R> dataStream) {
        // 两个输入是对等的
        return new ConnectedStreams<>(environment, this, dataStream);
    }

    public <R> BroadcastConnectedStream<T, R> connect(BroadcastStream<R> broadcastStream) {
        // DataStream使用状态，broadcastStream更新状态
        return new BroadcastConnectedStream<>(environment, this, ...);
    }

    public <K> KeyedStream<T, K> keyBy(KeySelector<T, K> key) {
        return new KeyedStream<>(this, clean(key));
    }

    // 自定义分区
    public <K> DataStream<T> partitionCustom(
            Partitioner<K> partitioner, KeySelector<T, K> keySelector) {
        return setConnectionType(
                new CustomPartitionerWrapper<>(clean(partitioner), clean(keySelector)));
    }

    public DataStream<T> shuffle() {
        // 随机分区
        return setConnectionType(new ShufflePartitioner<T>());
    }

    public DataStream<T> forward() {
        // 本地转发
        return setConnectionType(new ForwardPartitioner<T>());
    }

    public DataStream<T> rebalance() {
        // 轮流分发
        return setConnectionType(new RebalancePartitioner<T>());
    }


    public DataStream<T> rescale() {
        // 轮流分发到下一个环节的子集: 不同于rebalance，rescale是窄依赖
        return setConnectionType(new RescalePartitioner<T>());
    }

    public DataStream<T> global() {
        // 全部发给subTask=0
        return setConnectionType(new GlobalPartitioner<T>());
    }

    public <R> SingleOutputStreamOperator<R> map(
            MapFunction<T, R> mapper, TypeInformation<R> outputType) {
        return transform("Map", outputType, new StreamMap<>(clean(mapper)));
    }

    public <R> SingleOutputStreamOperator<R> flatMap(
            FlatMapFunction<T, R> flatMapper, TypeInformation<R> outputType) {
        return transform("Flat Map", outputType, new StreamFlatMap<>(clean(flatMapper)));
    }

    public <R> SingleOutputStreamOperator<R> process(
            ProcessFunction<T, R> processFunction, TypeInformation<R> outputType) {
        ProcessOperator<T, R> operator = new ProcessOperator<>(clean(processFunction));
        return transform("Process", outputType, operator);
    }

    public <T2> CoGroupedStreams<T, T2> coGroup(DataStream<T2> otherStream) {
        return new CoGroupedStreams<>(this, otherStream);
    }

    public <T2> JoinedStreams<T, T2> join(DataStream<T2> otherStream) {
        return new JoinedStreams<>(this, otherStream);
    }

    public DataStreamSink<T> sinkTo(Sink<T> sink) {
        return this.sinkTo(sink, CustomSinkOperatorUidHashes.DEFAULT);
    }

    public DataStreamSink<T> sinkTo(
            Sink<T> sink, CustomSinkOperatorUidHashes customSinkOperatorUidHashes) {
        // read the output type of the input Transform to coax out errors about MissingTypeInfo
        transformation.getOutputType();
        return DataStreamSink.forSink(this, sink, customSinkOperatorUidHashes);
    }

    public CloseableIterator<T> executeAndCollect(String jobExecutionName) throws Exception {
        return executeAndCollectWithClient(jobExecutionName).iterator;
    }

}

```


```java

// 主要api包含窗口和聚合
public class KeyedStream<T, KEY> extends DataStream<T> {

    private final KeySelector<T, KEY> keySelector;

    public <R> SingleOutputStreamOperator<R> process(
            KeyedProcessFunction<KEY, T, R> keyedProcessFunction, TypeInformation<R> outputType) {

        KeyedProcessOperator<KEY, T, R> operator =
                new KeyedProcessOperator<>(clean(keyedProcessFunction));
        return transform("KeyedProcess", outputType, operator);
    }

    public WindowedStream<T, KEY, GlobalWindow> countWindow(long size, long slide) {
        return window(GlobalWindows.create())
                .evictor(CountEvictor.of(size))
                .trigger(CountTrigger.of(slide));
    }

    public <W extends Window> WindowedStream<T, KEY, W> window(
            WindowAssigner<? super T, W> assigner) {
        return new WindowedStream<>(this, assigner);
    }

    public SingleOutputStreamOperator<T> reduce(ReduceFunction<T> reducer) {
        ReduceTransformation<T, KEY> reduce = new ReduceTransformation<>(..., clean(reducer), ...);
        getExecutionEnvironment().addOperator(reduce);
        return new SingleOutputStreamOperator<>(getExecutionEnvironment(), reduce);
    }

    public SingleOutputStreamOperator<T> sum(String field) {
        return aggregate(new SumAggregator<>(field, getType(), getExecutionConfig()));
    }

    protected SingleOutputStreamOperator<T> aggregate(AggregationFunction<T> aggregate) {
        return reduce(aggregate).name("Keyed Aggregation");
    }

}

```

核心api转换关系如下

![DataStreamApi](/assets/images/2025-04-01/DataStreamApi.png)


## Sink

`Sink`有两个版本, `sink.Sink`和`sink2.Sink`，前者已标记为`@deprecated`


### sink.Sink

```java

public interface Sink<InputT, CommT, WriterStateT, GlobalCommT> extends Serializable {

    SinkWriter<InputT, CommT, WriterStateT> createWriter(
            InitContext context, List<WriterStateT> states) throws IOException;

    // @return A committer for the 2-phase-commit protocol.
    Optional<Committer<CommT>> createCommitter() throws IOException;

    // @return A committer for the 2-phase-commit protocol.
    // GlobalCommitter是单实例的
    Optional<GlobalCommitter<CommT, GlobalCommT>> createGlobalCommitter() throws IOException;

}

public interface SinkWriter<InputT, CommT, WriterStateT> extends AutoCloseable {

    void write(InputT element, Context context) throws IOException, InterruptedException;

    // This will be called before we checkpoint the Writer's state
    // 两阶段提交协议的第一个阶段
    List<CommT> prepareCommit(boolean flush) throws IOException, InterruptedException;

    List<WriterStateT> snapshotState(long checkpointId) throws IOException;

}

public interface Committer<CommT> extends AutoCloseable {

    List<CommT> commit(List<CommT> committables) throws IOException, InterruptedException;

}

// 并行度固定为1
public interface GlobalCommitter<CommT, GlobalCommT> extends AutoCloseable {

    // 预合并
    GlobalCommT combine(List<CommT> committables) throws IOException;

    List<GlobalCommT> commit(List<GlobalCommT> globalCommittables);

    void endOfInput() throws IOException, InterruptedException;

}

```


### sink2.Sink

```java

public interface Sink<InputT> extends Serializable {

    SinkWriter<InputT> createWriter(WriterInitContext context) throws IOException;

}

// 运行时环境提供context信息
public interface InitContext {

    OptionalLong getRestoredCheckpointId();

    JobInfo getJobInfo();

    TaskInfo getTaskInfo();

}

public interface WriterInitContext extends InitContext {

    // 在数据处理间隙执行Runnable
    MailboxExecutor getMailboxExecutor();

    // 注册定时任务
    ProcessingTimeService getProcessingTimeService();

}

public interface SinkWriter<InputT> extends AutoCloseable {

    void write(InputT element, Context context) throws IOException, InterruptedException;

    // Called on checkpoint or end of input so that the writer to flush all pending data for at-least-once.
    void flush(boolean endOfInput) throws IOException, InterruptedException;

}

```

两个版本的区别

1. `v1`版本把`writer`和`committer`放到了一起，过于耦合，也不是所有的`sink`都需要这些高级功能
2. `GlobalCommitter`应该是全局一个实例，跟`writer`放一起感觉很奇怪
3. `v2`简化了接口，只保留了`writer`，`两阶段提交`等高级功能通过标记接口动态生成`committer`算子，详情请看下一篇！！！


## 总结

本文总结了`DataStream`常用的简单`api`，包括`source`、`sink`，常用的api：`filter、project、map`等，关于`window，join`等高级api后续会在专题中阐述


