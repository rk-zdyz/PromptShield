import matplotlib.pyplot as plt
import matplotlib.patches as patches

def generate_figure1(output_path="fig1_architecture.png"):
    fig, ax = plt.subplots(figsize=(10, 5.2), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 60)
    ax.axis('off')

    # Background header
    ax.text(50, 56.5, "PROMPT SHIELD — DEFENCE-IN-DEPTH ARCHITECTURE", 
            ha='center', va='center', fontsize=12, fontweight='bold', color='#1a1a1a')
    ax.text(50, 53.5, "Independent native checks at input, context, retrieval, action, and output boundaries", 
            ha='center', va='center', fontsize=8.5, fontstyle='italic', color='#4a5568')

    def draw_box(x, y, w, h, title, subtitle, bg_color='#ffffff', border_color='#2b6cb0', text_color='#1a202c', rx=1.5):
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0.2,rounding_size={rx}",
                                      ec=border_color, fc=bg_color, lw=1.3)
        ax.add_patch(rect)
        if subtitle:
            ax.text(x + w/2, y + h*0.62, title, ha='center', va='center', fontsize=8.5, fontweight='bold', color=text_color)
            ax.text(x + w/2, y + h*0.30, subtitle, ha='center', va='center', fontsize=7.0, color='#4a5568')
        else:
            ax.text(x + w/2, y + h*0.5, title, ha='center', va='center', fontsize=8.5, fontweight='bold', color=text_color)

    # 1. User / Application Input
    draw_box(2, 28, 14, 8, "User / App", "Input request & context", bg_color='#ebf8ff', border_color='#3182ce')

    # Left Column: Ingress & Retrieval Layers
    draw_box(20, 42, 21, 7.5, "L1 · Input Gate", "Unicode · Homoglyphs · Encodings", bg_color='#f7fafc', border_color='#4a5568')
    draw_box(20, 32.5, 21, 7.5, "L2 · Threat Detector", "Aho-Corasick (218 patterns) + ML", bg_color='#f7fafc', border_color='#4a5568')
    draw_box(20, 23, 21, 7.5, "L3 · Context Firewall", "Trust labels · Boundary isolation", bg_color='#f7fafc', border_color='#4a5568')
    draw_box(20, 13.5, 21, 7.5, "L4 · Retrieval Guard", "Provenance · Selective sanitization", bg_color='#f7fafc', border_color='#4a5568')

    # Center: Risk Engine
    draw_box(45.5, 25, 17, 13, "Risk Engine", "Multi-signal fusion R(x)\nGraduated policy π(x)", bg_color='#fffaf0', border_color='#dd6b20')

    # Right Column: Execution & Egress Guards
    draw_box(67, 39, 20, 8, "L5 · Action Guard", "Plan envelope · Scope verify", bg_color='#f7fafc', border_color='#4a5568')
    draw_box(67, 27.5, 20, 8, "LLM Runtime", "Sandboxed task execution", bg_color='#ebf8ff', border_color='#3182ce')
    draw_box(67, 16, 20, 8, "L6 · Output Guard", "Canary tokens · Egress checks", bg_color='#f7fafc', border_color='#4a5568')

    # Far Right: Response
    draw_box(90.5, 27.5, 8.5, 8, "Response", "Safe result", bg_color='#f0fff4', border_color='#38a169')

    # Bottom: Audit & Telemetry
    draw_box(20, 2.5, 67, 6.5, "Audit Plane & Telemetry Engine", 
             "Cryptographic hashes · Provenance DAG · Latency metrics (µs) · Threat telemetry", 
             bg_color='#f7fafc', border_color='#718096')

    # Connectors & Arrows
    arrow_kw = dict(arrowstyle="->", color="#4a5568", lw=1.2, mutation_scale=11)
    
    # User to Layers
    ax.annotate("", xy=(20, 45.7), xytext=(16, 32), arrowprops=arrow_kw)
    ax.annotate("", xy=(20, 36.2), xytext=(16, 32), arrowprops=arrow_kw)
    ax.annotate("", xy=(20, 26.7), xytext=(16, 32), arrowprops=arrow_kw)
    ax.annotate("", xy=(20, 17.2), xytext=(16, 32), arrowprops=arrow_kw)

    # Layers to Risk Engine
    ax.annotate("", xy=(45.5, 34), xytext=(41, 45.7), arrowprops=arrow_kw)
    ax.annotate("", xy=(45.5, 32.5), xytext=(41, 36.2), arrowprops=arrow_kw)
    ax.annotate("", xy=(45.5, 30.5), xytext=(41, 26.7), arrowprops=arrow_kw)
    ax.annotate("", xy=(45.5, 28), xytext=(41, 17.2), arrowprops=arrow_kw)

    # Risk Engine to L5 & LLM
    ax.annotate("", xy=(67, 43), xytext=(62.5, 33), arrowprops=arrow_kw)
    ax.annotate("", xy=(67, 31.5), xytext=(62.5, 31.5), arrowprops=arrow_kw)

    # L5 to LLM Runtime
    ax.annotate("", xy=(77, 35.5), xytext=(77, 39), arrowprops=arrow_kw)
    ax.text(78.5, 37.2, "allow", fontsize=7, color='#2b6cb0', fontweight='bold')

    # LLM to L6
    ax.annotate("", xy=(77, 24), xytext=(77, 27.5), arrowprops=arrow_kw)

    # L6 to Response
    ax.annotate("", xy=(90.5, 31.5), xytext=(87, 20), arrowprops=arrow_kw)

    # Telemetry connections
    dash_arrow = dict(arrowstyle="->", color="#a0aec0", lw=0.9, ls="--", mutation_scale=9)
    ax.annotate("", xy=(53.5, 9), xytext=(53.5, 25), arrowprops=dash_arrow)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Generated {output_path}")

def generate_figure2(output_path="fig2_pipeline.png"):
    fig, ax = plt.subplots(figsize=(10, 2.6), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 30)
    ax.axis('off')

    ax.text(50, 26.5, "PROMPT SHIELD REQUEST PROCESSING PIPELINE", 
            ha='center', va='center', fontsize=11, fontweight='bold', color='#1a1a1a')

    stages = [
        ("Collect", "Prompt + source"),
        ("Label", "Trust + provenance"),
        ("Detect", "Rules + ML (µs)"),
        ("Decide", "Risk + policy R(x)"),
        ("Constrain", "Context + tools"),
        ("Verify", "Output + egress"),
        ("Record", "Audit trail")
    ]

    w, h = 11.5, 11
    start_x = 2.5
    gap = 2.4
    arrow_kw = dict(arrowstyle="->", color="#2b6cb0", lw=1.4, mutation_scale=12)

    for i, (title, sub) in enumerate(stages):
        x = start_x + i * (w + gap)
        y = 10.5
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.2,rounding_size=1.2",
                                      ec='#3182ce', fc='#f7fafc', lw=1.2)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h*0.62, title, ha='center', va='center', fontsize=8.5, fontweight='bold', color='#1a365d')
        ax.text(x + w/2, y + h*0.30, sub, ha='center', va='center', fontsize=6.8, color='#4a5568')

        if i < len(stages) - 1:
            ax.annotate("", xy=(x + w + gap, y + h/2), xytext=(x + w, y + h/2), arrowprops=arrow_kw)

    ax.text(50, 4.0, "Decision outcomes:  ALLOW  ·  SANITIZE  ·  ISOLATE  ·  REQUIRE APPROVAL  ·  BLOCK", 
            ha='center', va='center', fontsize=8.0, fontweight='bold', color='#2d3748')

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Generated {output_path}")

if __name__ == "__main__":
    generate_figure1("d:/PromptShield/fig1_architecture.png")
    generate_figure2("d:/PromptShield/fig2_pipeline.png")
