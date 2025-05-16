# 使用LLM检测代码是否为恶意

## project mode

1. 输入一个文件路径
2. 递归遍历路径下的所有文件
3. 把文件逐个交给LLM，判断是否为恶意代码，输出结构化的结果（至少包含恶意概率，判断理由）
4. 输出结构化的结果

## gitlab job mode

1. 在gitlab仓库发生merge request时触发
2. 找到这次merge request中发生变化的所有文件
3. 逐个交给LLM判断是否为恶意代码


注意事项：
1. LLM使用deepseek api
2. 代码中所有注释用英文写
3. 当前目录名为CodeSheriff，就在这个目录下工作 