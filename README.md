# 🎉 Maxin_attack_defense_bot

#### 🧑‍💻 小组成员：马馨 金泰霖 王家辉

---

## 🚀 项目名称

基于大模型的网络安全基础知识问答 - 软件工程探索与实践(1)期中大作业

## 📝 项目简介

本项目通过构建一个基于大模型的网络安全基础知识问答系统，帮助用户快速获取与网络安全相关的各类信息。

#### ✨ 项目的技术核心：

* RAG 检索增强生成：利用 RAG（Retrieval-Augmented Generation）技术，结合自建语料库和基础知识库，增强大模型的生成能力，使其在回答用户提问时更为精准与专业。

* 提示词工程：通过对提示词进行优化和安全过滤，确保生成的答案既符合实际应用场景，又具备安全性，避免出现敏感内容或不当回复。

* 前端交互：前端基于简单易用的 HTML 页面，支持用户与后端智能问答系统进行实时交互，快速获取网络安全领域的专业知识。

* 自建语料库：项目中使用了多个自建的网络安全语料文件，确保问答系统能够在特定领域提供高质量的答案。

通过本系统，用户能够有效进行网络安全知识问答查询，同时该系统也可扩展为更多专业领域的知识问答平台。

---

## ⚙️ 安装方法

#### 第 1 步：创建并激活虚拟环境
```bash
conda create -n attack-bot python=3.12
conda activate attack-bot
```

#### 第 2 步：克隆项目仓库
```bash
git clone https://github.com/JinTailin/Maxin_attack_defense_bot.git
```

#### 第 3 步：进入项目目录
```bash
cd Maxin_attack_defense_bot
```

#### 第 4 步：安装项目依赖
```bash
pip install -r requirements.txt
```
   
## 💻 使用方法

#### 第 1 步：进入项目目录
```bash
cd Maxin_attack_defense_bot
```

#### 第 2 步：启动服务器
```bash
cd python server.py
```

#### 第 3 步：打开 `Maxin_attack_defense_bot` 目录中的 `index.html`

#### 第 4 步：开始与问答大模型对话！

---

## 📂 项目结构
```
.
├── .gitignore                               # Git 忽略的文件或文件夹列表
├── index.html                               # 前端页面，用于与网络安全问答大模型交互对话
├── ingest_data_dir_safe.py                  # 文本语料处理脚本
├── ingest_jsonl_mcq.py                      # 选择题语料处理脚本
├── README.md                                # 项目说明文件，包含项目简介、安装和使用方法、项目结构等
├── requirements.txt                         # 项目依赖列表，使用 pip 安装所需的库
├── server.py                                # 智能路由 API 服务，连接前端和后端
├── attack_defense_bot/                      # 主要的 Python 代码库，包含了项目的核心逻辑
│   ├── __init__.py                          # 包含模块初始化代码
│   ├── api_client.py                        # 封装 search 和 dialogue 两个 HTTP 调用
│   ├── config.py                            # 读取环境变量并保存常量
│   ├── data_processor.py                    # 对 /search 结果做二次整理
│   ├── guard.py                             # 安全相关的保护逻辑，如输入校验、数据审计等
│   ├── main.py                              # 完整流程入口
│   ├── prompt_builder.py                    # 组合并产生最终的 prompt
│   └── utils.py                             # 工具类代码，包含辅助功能或常用的函数
└── data/                                    # 自建语料库的数据
    ├── adobe.txt            
    ├── bad_power.txt        
    ├── Domain_Borrowing.txt            
    ├── Ghidra.txt                      
    ├── length_side_channel.txt              
    ├── MCQs_2730.jsonl              
    ├── SAQs_270.jsonl             
    ├── software_protect_suggestion.txt      
    ├── wechat.txt                            
    └── Xdebug.txt                      
```