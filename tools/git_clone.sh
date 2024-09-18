#!/bin/bash
set -x

# 从命令行获取项目URL和分支名称
PROJECT_URL=$1
BRANCH_NAME=${2:-main}

# 从URL中提取项目名称
PROJECT_NAME=$(basename -s .git $PROJECT_URL)

# 新建目录并进入
mkdir $PROJECT_NAME && cd $PROJECT_NAME

# 初始化Git仓库
git init

# 设置重试次数
RETRY_LIMIT=2000

# 开始fetch操作
num=1
while [ $num -le $RETRY_LIMIT ]; do
   git fetch $PROJECT_URL
   if [ $? -ne 0 ]; then
       echo "Fetch failed, retrying ($num/$RETRY_LIMIT)..."
       num=$(($num+1))
   else
       echo "Fetch succeeded."
       break
   fi
done

# 如果fetch成功，继续执行后续步骤
if [ $num -le $RETRY_LIMIT ]; then
    # 切换到FETCH_HEAD
    git checkout FETCH_HEAD

    # 添加远程仓库
    git remote add origin $PROJECT_URL

    # 拉取指定分支
    git pull origin $BRANCH_NAME

    # 检查是否需要再次拉取
    git checkout $BRANCH_NAME
    git pull
else
    echo "Failed to fetch project after $RETRY_LIMIT attempts."
fi