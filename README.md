# Maxin_attack_defense_bot

## 用法

1. 创建conda虚拟环境 & 安装项目依赖：
   conda create -n attack-bot python=3.12
   conda activate attack-bot
   pip install -r requirements.txt

2. 运行直接模式查询：（示例问题：防火墙的作用是什么？）
   
   python -m attack_defense_bot.main --mode direct --query "防火墙的作用是什么？"

3. 运行检索增强生成模式查询：（示例问题：如何防御SQL注入？）
   
   python -m attack_defense_bot.main --mode rag --db common_dataset --top-k 5 --query "如何防御SQL注入？"