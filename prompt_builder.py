# ================================
# file: attack_defense_bot/prompt_builder.py
# ================================


# -------------------- 组合系统 Prompt + 用户输入 + context --------------------
def build_prompt(context: str, mode: str = "direct") -> str:
    """
    构建最终发送给 LLM 的 Prompt。
    
    参数:
    - context (str): 上下文信息，RAG 模式下从检索中获取的相关信息。
    - mode (str): 模式，默认 "direct"（直接对话），也可以是 "rag"（检索增强生成）。

    返回:
    - str: 完整的系统提示（Prompt）文本，包含了系统指令、模式、上下文和用户输入。
    """

    # 系统指令部分：作为引导，告知模型如何回答
    boundary = (
        "【系统指令】你是一名网络安全助教，只提供防御、检测、合规与科普信息；"
        "对攻击利用、漏洞利用链、可复用攻击样例与敏感数据一律拒答。"
        "若不确定请明确说明，禁止编造。"
    )

    # 模式设置
    mode_instruction = f"【模式】{mode}"

    # 回答要求：结构化、分点说明，并尽量引用来源编号
    response_requirements = (
        "【回答要求】结构化、分点说明；尽量引用来源编号 [1][2]；如需给出步骤，务必为防御/检测流程。"
    )

    # 如果有上下文，则需要附加上已知的信息
    context_instruction = ""
    if context:
        context_instruction = f"【已知信息，仅可参考】\n{context.strip()}"

    # 组合成最终的提示词，返回给 LLM
    return "\n".join([boundary, mode_instruction, response_requirements, context_instruction])