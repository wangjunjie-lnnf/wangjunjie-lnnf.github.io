---
layout: post
title:  "SystemVerilog基础"
date:   2024-02-13 02:22:07 +0000
categories: jekyll
tags: hardware
---

# SystemVerilog基础

![sv-vs-v](/assets/images/2024-02-13/sv-vs-v.png)

Verilog和SystemVerilog的关系有点类型C和C++的关系，SystemVerilog完全兼容Verilog，本文只专注于SystemVerilog新增的部分。

## 数据类型

### Variable types

> Variables are used as temporary storage for programming. This temporary storage is for simulation. Actual silicon often does not need the same temporary storage, depending on the programming context in which the variable is used. Variables are required on the left-hand side of procedural block assignments. 

变量类型在仿真时需要临时存储，综合时根据场景可能会用DFF代替，过程块的左操作数必须是变量类型

![sv-var-types](/assets/images/2024-02-13/sv-var-types.png)

> The reg data type is an obsolete data type left over from the original Verilog language. The logic type should be used instead of reg. The original Verilog language used the reg data type as a general purpose variable. Unfortunately, the use of keyword reg is a misnomer that might seem to be short for “register”, a hardware device built with flip-flops. In actuality, there is no correlation between using a reg variable and the hardware that is inferred. It is the context in which a variable is used that determines if the hardware represented is combinational logic or sequential flip-flop logic. Using logic instead of reg can help prevent this misconception that a hardware register will be inferred.

最大的变化是使用logic类型代替verilog中的reg类型，理由是reg容易让人误解为register，事实上reg的含义跟所在过程快是组合电路还是时序电路有关。


### Net types

> Nets are used to connect design blocks together. A net transfers data values from a source, referred to as a driver, to a destination or receiver. Nets differ from variables in three significant ways: 

1. Nets do not have temporary storage like variables. Instead, nets reflect the current value of the driver(s) of the net. 

2. Nets can resolve the resultant value of multiple drivers, where variables can only have a single source (if multiple procedural assignments are made to a variable, the last assignment is the resultant value, rather than resolving the result of all assignments)

3. Nets reflect both a driver value (0, 1, Z or X) and a driver strength.

![sv-net-types](/assets/images/2024-02-13/sv-net-types.png)

net类型用于块之间的连接，不需要临时存储，表示的是driver的当前值


## 过程块

> SystemVerilog has four types of always procedures: a general purpose procedure using the keyword **always**, and specialized always procedures that use the keywords **always_ff**, **always_comb** and **always_latch**. The always_ff, always_comb and always_latch specialized always procedural blocks behave the same as the general purpose always procedural block, but impose important coding restrictions required by synthesis. These additional restrictions help to ensure that the behavior of RTL simulations will match the gate-level behavior of the actual ASIC or FPGA. As the names of these specialized procedures suggest, always_ff imposes certain synthesis restrictions required for modeling sequential logic devices such as flip-flops. The always_comb procedure imposes certain synthesis restrictions for modeling combinational logic such as decoders, and always_latch imposes certain synthesis restrictions for modeling latched behavior. 

SystemVerilog新增了3个特殊化的always变体：always_ff、always_comb、always_latch，他们在always的基础上增加了一些额外的约束，编译时可以更好的检查行为是否符合约束。


## 组合逻辑

### always and always_comb

> When using the general purpose **always** procedure, synthesis compilers impose several coding restrictions that the RTL design engineer must be aware of and adhere to. These restriction include:

1. The procedure sensitivity list should include every signal for which the value can affect the output(s) of the combinational logic. 

2. The procedure sensitivity list must be sensitive to all possible value changes of each signal. It cannot contain **posedge** or **negedge** keywords that limit the sensitivity to specific changes.

3. The procedure should execute in zero simulation time, and should not contain any form of propagation delay using **#, @ or wait** time controls. 

4. A variable assigned a value in a combinational logic procedure should not be assigned a value by any other procedure or continuous assignment. (Multiple assignments within the same procedure are permitted.)

> The RTL-specific **always_comb** automatically enforces the coding restrictions listed above, and it will automatically trigger once at the start of simulation, to ensure that all variables assigned in the procedure accurately reflect the values of the inputs to the procedure at simulation time zero.

`always_comb`自动检查组合电路需要满足的4个规则，简化编码，对比以下示例：

```verilog
always @ (a, b, mode) begin
    if (!mode) result = a + b;
    else       result = a - b; 
end

always_comb begin
    if (!mode) result = a + b;
    else       result = a - b; 
end
```

## 时序逻辑

> Synthesis compilers will attempt to infer a flip-flop when the sensitivity list of an always procedure contains the keyword **posedge** or **negedge**. However, synthesis compilers also require additional code restrictions be met in order to infer a flip-flop.

1. The procedure sensitivity list must specify which edge of the clock triggers updating the state of the flip-flop (**posedge** or **negedge**).

2. The sensitivity list must specify the leading edge (**posedge** or **negedge**) of any asynchronous set or reset signals (synchronous sets or resets are not listed in the sensitivity list).

3. Other than the clock, asynchronous set or asynchronous reset, the sensitivity list cannot contain any other signals, such as the D input or an enable input.

4. The procedure should execute in zero simulation time. Synthesis compilers ignore \# delays, and do not permit @ or wait time controls. An exception to this rule is the use of intra-assignment unit delays.

5. A variable assigned a value in a sequential logic procedure cannot be assigned a value by any other procedure or continuous assignment (multiple assignments within the same procedure are permitted).

6. A variable assigned a value in a sequential logic procedure cannot have a mix of blocking and nonblocking assignments.

> The **always_ff** procedure also requires a sensitivity list that specifies a **posedge** or **negedge** of a clock, but **always_ff** also enforces many of the synthesis requirements listed above. The sensitivity list cannot be inferred from the body of the procedure, The reason is simple. The clock signal is not named within the body of the **always_ff** procedure. The clock name, and which edge of the clock triggers the procedure, must be explicitly specified by the design engineer in the sensitivity list.

always_ff会自动检查时序逻辑要满足的6个规则


## Modeling Latches

> From an RTL modeling perspective, a latch is a cross of combinational logic and sequential logic. Latches do not have a clock, and do not change on a positive or negative edge transition. With latches, the output value is based on the values of the inputs, which is the behavior of combinational logic. However, latches also have storage characteristics. The output value is a reflection of both the input values and the state of the internal storage, which is the behavior of sequential logic.

latch同时具有组合逻辑和时序逻辑的部分特性：没有clock但是有内部存储，输出信号依赖输入信号和内部存储

> SystemVerilog adds an RTL-specific always_latch procedure to the original Verilog language. Using always_latch documents that it is intended to have latched behavior in the procedure. Software tools, such as lint checkers and synthesis compilers, can issue warnings or errors if the procedure does not represent latched functionality. The always_latch is an always procedure with additional modeling rules to help ensure that RTL code adheres to synthesis requirements. These rules are:

1. A complete combinational logic sensitivity list is automatically inferred. This automatic sensitivity list includes all signals that are read within the procedure.

2. Using #, @ or wait to delay execution of a statement in an always_latch procedure is not permitted, enforcing the synthesis guideline for using zero-delay procedures. 

3. Any variable assigned a value in an always_latch procedure cannot be assigned from another procedure or continuous assignment, which is a restriction required by synthesis compilers.


> Synthesis will infer a latch whenever a non-clocked always procedure is entered, and there is a possibility that one or more of the variables used on the left-hand side of assignment statements will not be updated. 

在不包含clock的always块中，左操作数如果可能出现未更新的情况，则认为此操作数是一个latch，例如：

```verilog
always_comb begin // 3-to-1 mux
    case (select)
        2'b00: y = a;
        2'b01: y = b;
        2'b10: y = c;
    endcase
end

always_comb begin // add or sub
    case (mode)
        1'b0: add_result = a + b;
        l'b1: sub_result = a - b;
    endcase
end
```

> When an incomplete decision statement is appropriate for the design functionality, the design engineer needs to let synthesis compilers know that the unspecified decision expression values can be ignored. There are several ways to tell synthesis that all values used by the decision statement have been specified, and, therefore, latches are not needed. Five common coding styles are:

1. Use a **default** case item within the case statement that assigns known output values.

2. Use a pre-case assignment before the case statement that assigns known output values.

3. Use the unique and priority decision modifiers.

4. Use an X assignment value to indicate “don’t care” conditions

避免latch的方式是case末尾增加default，或者在case之前先设置默认值

```verilog
always_comb begin
    case (current_state)
        RESET   : next_state = READY;
        READY   : next_state = SET;
        SET     : next_state = GO;
        GO      : next_state = READY;
        default : next_state = RESET;   // reset if error
    endcase
end

always_comb begin
    next_state = RESET; // default to reset if invalid state
    case (current_state)
        RESET   : next_state = READY;
        READY   : next_state = SET;
        SET     : next_state = GO;
        GO      : next_state = READY;
    endcase
end
```

