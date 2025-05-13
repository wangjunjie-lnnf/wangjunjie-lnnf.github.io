---
layout: post
title:  flink-Transformation
date:   2025-04-02 22:49:07 +0000
categories: bigdata
tags: bigdata,flink
---

# flink: Transformation

flink版本为`1.19.1`  

如果给api分层次，`DataStream`是上层api，`Transformation`是下层api，每个上层的api最终都转换成了下层的api。  

以`map`为例


```java

public class StreamExecutionEnvironment implements AutoCloseable {

    protected final List<Transformation<?>> transformations = new ArrayList<>();

}

public class DataStream<T> {

    public <R> SingleOutputStreamOperator<R> map(MapFunction<T, R> mapper) {
        TypeInformation<R> outType = TypeExtractor.getMapReturnTypes(...);
        return map(mapper, outType);
    }

    public <R> SingleOutputStreamOperator<R> map(
            MapFunction<T, R> mapper, TypeInformation<R> outputType) {
        return transform("Map", outputType, new StreamMap<>(clean(mapper)));
    }

    public <R> SingleOutputStreamOperator<R> transform(
            String operatorName,
            TypeInformation<R> outTypeInfo,
            OneInputStreamOperator<T, R> operator) {
        return doTransform(operatorName, outTypeInfo, SimpleOperatorFactory.of(operator));
    }

    protected <R> SingleOutputStreamOperator<R> doTransform(
            String operatorName,
            TypeInformation<R> outTypeInfo,
            StreamOperatorFactory<R> operatorFactory) {

        // read the output type of the input Transform to coax out errors about MissingTypeInfo
        transformation.getOutputType();

        OneInputTransformation<T, R> resultTransform =
                new OneInputTransformation<>(
                        this.transformation,
                        operatorName,
                        operatorFactory,
                        outTypeInfo,
                        environment.getParallelism(),
                        false);

        SingleOutputStreamOperator<R> returnStream =
                new SingleOutputStreamOperator(environment, resultTransform);

        // 收集Transformation
        getExecutionEnvironment().addOperator(resultTransform);

        return returnStream;
    }

}

```

## Transformation

```java

// Transformation包含了用户通过高级api指定的各种信息
// 唯独缺少了map、filter之类的udf的信息
public abstract class Transformation<T> {

    // 自动生成的唯一标识
    protected final int id;

    protected String name;

    protected String description;

    protected TypeInformation<T> outputType;

    private int parallelism;

    private int maxParallelism = -1;

    // 用户指定，用于重启之后状态恢复
    private String uid;

    // 相同key的算子的subtask调度到相同的slot中运行
    private Optional<SlotSharingGroup> slotSharingGroup;

    // 相同key的算子的相同index的subtask必须调度到同一个tm中，用于迭代型任务
    private String coLocationGroupKey;

}

```

## Transformation层次结构

![TransformationClass-1](/assets/images/2025-04-02/TransformationClass-1.png)

![TransformationClass-2](/assets/images/2025-04-02/TransformationClass-2.png)


```java



```


