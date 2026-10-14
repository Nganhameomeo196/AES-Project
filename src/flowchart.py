"""
==========================================================
              AES-128 FLOWCHART
        ENCRYPTION <-> DECRYPTION
==========================================================

AES-128:
    - Block size : 128 bit
    - Key size   : 128 bit
    - Nr         : 10 rounds

Encryption:
    Plaintext
        ↓
    State 4×4
        ↓
    AddRoundKey[0]
        ↓
    9 Main Rounds
        ↓
    Final Round
        ↓
    Ciphertext

Decryption:
    Ciphertext
        ↓
    State 4×4
        ↓
    AddRoundKey[10]
        ↓
    9 Main Rounds
        ↓
    Final Round
        ↓
    Plaintext

Output:
    AES_Flowchart_Method.png
==========================================================
"""

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.patches import (
    FancyBboxPatch,
    FancyArrowPatch
)


# ==========================================================
# 1. CẤU HÌNH
# ==========================================================

plt.rcParams["font.family"] = "DejaVu Sans"


# ==========================================================
# 2. MÀU SẮC
# ==========================================================

BG = "#F8FAFC"

TEXT = "#1E293B"
SUBTEXT = "#64748B"

BLUE = "#2563EB"
BLUE_LIGHT = "#EFF6FF"
BLUE_BORDER = "#93C5FD"

ORANGE = "#EA580C"
ORANGE_LIGHT = "#FFF7ED"
ORANGE_BORDER = "#FDBA74"

GREEN = "#16A34A"
GREEN_LIGHT = "#F0FDF4"
GREEN_BORDER = "#86EFAC"

PURPLE = "#7C3AED"
PURPLE_LIGHT = "#F5F3FF"
PURPLE_BORDER = "#C4B5FD"

GRAY = "#F1F5F9"
GRAY_BORDER = "#CBD5E1"

WHITE = "#FFFFFF"

ARROW = "#475569"


# ==========================================================
# 3. HÀM VẼ SHADOW
# ==========================================================

def draw_shadow(ax, x, y, w, h, radius=0.08):

    shadow = FancyBboxPatch(
        (x + 0.035, y - 0.035),
        w,
        h,
        boxstyle=f"round,pad=0,rounding_size={radius}",
        linewidth=0,
        facecolor="#000000",
        alpha=0.06,
        zorder=1
    )

    ax.add_patch(shadow)


# ==========================================================
# 4. HÀM VẼ BOX
# ==========================================================

def draw_box(
    ax,
    x,
    y,
    w,
    h,
    text,
    facecolor=WHITE,
    edgecolor=GRAY_BORDER,
    textcolor=TEXT,
    fontsize=10,
    bold=True,
    radius=0.08
):

    draw_shadow(ax, x, y, w, h, radius)

    box = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle=f"round,pad=0,rounding_size={radius}",
        linewidth=1.4,
        edgecolor=edgecolor,
        facecolor=facecolor,
        zorder=2
    )

    ax.add_patch(box)

    ax.text(
        x + w / 2,
        y + h / 2,
        text,
        ha="center",
        va="center",
        fontsize=fontsize,
        color=textcolor,
        fontweight="bold" if bold else "normal",
        zorder=3
    )


# ==========================================================
# 5. BOX CÓ 2 DÒNG
# ==========================================================

def draw_double_box(
    ax,
    x,
    y,
    w,
    h,
    title,
    subtitle,
    facecolor,
    edgecolor,
    title_color
):

    draw_shadow(ax, x, y, w, h)

    box = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0,rounding_size=0.08",
        linewidth=1.5,
        edgecolor=edgecolor,
        facecolor=facecolor,
        zorder=2
    )

    ax.add_patch(box)

    ax.text(
        x + w / 2,
        y + h * 0.62,
        title,
        ha="center",
        va="center",
        fontsize=10,
        color=title_color,
        fontweight="bold",
        zorder=3
    )

    ax.text(
        x + w / 2,
        y + h * 0.30,
        subtitle,
        ha="center",
        va="center",
        fontsize=7.2,
        color=SUBTEXT,
        style="italic",
        zorder=3
    )


# ==========================================================
# 6. MŨI TÊN
# ==========================================================

def draw_arrow(ax, x, y1, y2, color=ARROW):

    arrow = FancyArrowPatch(
        (x, y1),
        (x, y2),
        arrowstyle="-|>",
        mutation_scale=14,
        linewidth=1.5,
        color=color,
        shrinkA=0,
        shrinkB=0,
        zorder=4
    )

    ax.add_patch(arrow)


# ==========================================================
# 7. KHỐI MAIN ROUND
# ==========================================================

def draw_main_round(
    ax,
    x,
    y,
    w,
    h,
    encryption=True
):

    # ------------------------------------------------------
    # Khung lớn
    # ------------------------------------------------------

    if encryption:
        face = BLUE_LIGHT
        edge = BLUE
        title_color = BLUE
    else:
        face = PURPLE_LIGHT
        edge = PURPLE
        title_color = PURPLE

    draw_shadow(ax, x, y, w, h, 0.10)

    block = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0,rounding_size=0.10",
        linewidth=1.8,
        edgecolor=edge,
        facecolor=face,
        zorder=2
    )

    ax.add_patch(block)


    # ------------------------------------------------------
    # Tiêu đề
    # ------------------------------------------------------

    if encryption:
        title = "MAIN ROUNDS × 9"
    else:
        title = "MAIN ROUNDS × 9"

    ax.text(
        x + w / 2,
        y + h - 0.27,
        title,
        ha="center",
        va="center",
        fontsize=11,
        color=title_color,
        fontweight="bold",
        zorder=4
    )

    ax.text(
        x + w / 2,
        y + h - 0.55,
        "(round = 1 ... 9)"
        if encryption
        else "(round = 9 ... 1)",
        ha="center",
        va="center",
        fontsize=7,
        color=SUBTEXT,
        style="italic",
        zorder=4
    )


    # ------------------------------------------------------
    # Các bước
    # ------------------------------------------------------

    if encryption:

        steps = [
            "1. SubBytes",
            "2. ShiftRows",
            "3. MixColumns",
            "4. AddRoundKey[round]"
        ]

    else:

        steps = [
            "1. InvShiftRows",
            "2. InvSubBytes",
            "3. AddRoundKey[round]",
            "4. InvMixColumns"
        ]


    step_w = w - 0.55
    step_h = 0.34

    start_y = y + h - 0.97

    for i, step in enumerate(steps):

        current_y = start_y - i * 0.44

        draw_box(
            ax,
            x + 0.275,
            current_y,
            step_w,
            step_h,
            step,
            WHITE,
            edge,
            TEXT,
            fontsize=7.5,
            bold=True,
            radius=0.045
        )

        if i < len(steps) - 1:

            draw_arrow(
                ax,
                x + w / 2,
                current_y - 0.09,
                current_y - 0.17,
                "#94A3B8"
            )


    # ------------------------------------------------------
    # Vòng lặp
    # ------------------------------------------------------

    loop_x = x + w + 0.18

    ax.annotate(
        "",
        xy=(loop_x, y + 0.25),
        xytext=(loop_x, y + h - 0.25),
        arrowprops=dict(
            arrowstyle="-|>",
            color=edge,
            lw=1.4,
            connectionstyle="arc3,rad=-0.55"
        )
    )

    ax.text(
        loop_x + 0.15,
        y + h / 2,
        "lặp\n9 lần",
        ha="left",
        va="center",
        fontsize=7,
        color=edge,
        fontweight="bold",
        style="italic"
    )


# ==========================================================
# 8. FINAL ROUND
# ==========================================================

def draw_final_round(
    ax,
    x,
    y,
    w,
    h,
    encryption=True
):

    draw_shadow(ax, x, y, w, h, 0.10)

    box = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0,rounding_size=0.10",
        linewidth=1.8,
        edgecolor=ORANGE,
        facecolor=ORANGE_LIGHT,
        zorder=2
    )

    ax.add_patch(box)


    # ------------------------------------------------------
    # Title
    # ------------------------------------------------------

    if encryption:
        title = "FINAL ROUND"
        round_text = "round = 10"
    else:
        title = "FINAL ROUND"
        round_text = "round = 0"

    ax.text(
        x + w / 2,
        y + h - 0.27,
        title,
        ha="center",
        va="center",
        fontsize=10,
        color=ORANGE,
        fontweight="bold",
        zorder=4
    )

    ax.text(
        x + w / 2,
        y + h - 0.50,
        round_text,
        ha="center",
        va="center",
        fontsize=7,
        color=SUBTEXT,
        style="italic",
        zorder=4
    )


    # ------------------------------------------------------
    # Steps
    # ------------------------------------------------------

    if encryption:

        steps = [
            "1. SubBytes",
            "2. ShiftRows",
            "3. AddRoundKey[10]"
        ]

        note = "Không có MixColumns"

    else:

        steps = [
            "1. InvShiftRows",
            "2. InvSubBytes",
            "3. AddRoundKey[0]"
        ]

        note = "Không có InvMixColumns"


    step_w = w - 0.55
    step_h = 0.34

    start_y = y + h - 0.87

    for i, step in enumerate(steps):

        current_y = start_y - i * 0.43

        draw_box(
            ax,
            x + 0.275,
            current_y,
            step_w,
            step_h,
            step,
            WHITE,
            ORANGE_BORDER,
            TEXT,
            fontsize=7.4,
            bold=True,
            radius=0.045
        )

        if i < len(steps) - 1:

            draw_arrow(
                ax,
                x + w / 2,
                current_y - 0.01,
                current_y - 0.13,
                "#A8A29E"
            )


    # ------------------------------------------------------
    # Note
    # ------------------------------------------------------

    ax.text(
        x + w / 2,
        y + 0.14,
        "✕ " + note,
        ha="center",
        va="center",
        fontsize=6.8,
        color=ORANGE,
        fontweight="bold",
        style="italic"
    )


# ==========================================================
# 9. VẼ MỘT CỘT
# ==========================================================

def draw_side(
    ax,
    center,
    encryption=True
):

    # ------------------------------------------------------
    # Tiêu đề
    # ------------------------------------------------------

    if encryption:
        title = "ENCRYPTION"
        title_color = BLUE
        input_text = "PLAINTEXT"
        output_text = "CIPHERTEXT"
    else:
        title = "DECRYPTION"
        title_color = PURPLE
        input_text = "CIPHERTEXT"
        output_text = "PLAINTEXT"


    ax.text(
        center,
        11.45,
        title,
        ha="center",
        va="center",
        fontsize=15,
        color=title_color,
        fontweight="bold"
    )

    ax.text(
        center,
        11.10,
        "AES-128",
        ha="center",
        va="center",
        fontsize=8.5,
        color=SUBTEXT,
        style="italic"
    )


    # ------------------------------------------------------
    # START
    # ------------------------------------------------------

    draw_box(
        ax,
        center - 1.45,
        10.05,
        2.9,
        0.58,
        input_text + " (128 bit)",
        GRAY,
        GRAY_BORDER,
        TEXT,
        fontsize=9
    )

    draw_arrow(
        ax,
        center,
        10.05,
        9.68
    )


    # ------------------------------------------------------
    # STATE
    # ------------------------------------------------------

    draw_box(
        ax,
        center - 1.45,
        9.05,
        2.9,
        0.58,
        "State 4 × 4",
        GRAY,
        GRAY_BORDER,
        TEXT,
        fontsize=9
    )

    draw_arrow(
        ax,
        center,
        9.05,
        8.68
    )


    # ------------------------------------------------------
    # INITIAL / ADD ROUND KEY
    # ------------------------------------------------------

    if encryption:

        key_title = "AddRoundKey[0]"
        key_sub = "State XOR RoundKey[0]"

    else:

        key_title = "AddRoundKey[10]"
        key_sub = "State XOR RoundKey[10]"


    draw_double_box(
        ax,
        center - 1.45,
        7.98,
        2.9,
        0.68,
        key_title,
        key_sub,
        ORANGE_LIGHT,
        ORANGE_BORDER,
        ORANGE
    )

    draw_arrow(
        ax,
        center,
        7.98,
        7.60
    )


    # ------------------------------------------------------
    # MAIN ROUND
    # ------------------------------------------------------

    draw_main_round(
        ax,
        center - 1.45,
        5.05,
        2.9,
        2.35,
        encryption
    )

    draw_arrow(
        ax,
        center,
        5.05,
        4.67
    )


    # ------------------------------------------------------
    # FINAL ROUND
    # ------------------------------------------------------

    draw_final_round(
        ax,
        center - 1.45,
        2.45,
        2.9,
        2.05,
        encryption
    )

    draw_arrow(
        ax,
        center,
        2.45,
        2.05
    )


    # ------------------------------------------------------
    # END
    # ------------------------------------------------------

    draw_box(
        ax,
        center - 1.45,
        1.30,
        2.9,
        0.62,
        output_text + " (128 bit)",
        GREEN_LIGHT,
        GREEN_BORDER,
        GREEN,
        fontsize=9
    )


# ==========================================================
# 10. MAIN
# ==========================================================

def main():

    # ------------------------------------------------------
    # Tạo figure ngang
    # ------------------------------------------------------

    fig, ax = plt.subplots(
        figsize=(13, 9)
    )

    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)

    ax.set_xlim(0, 13)
    ax.set_ylim(0.8, 13.1)

    ax.axis("off")


    # ------------------------------------------------------
    # Tiêu đề chung
    # ------------------------------------------------------

    ax.text(
        6.5,
        11.88,
        "AES-128 ENCRYPTION ↔ DECRYPTION",
        ha="center",
        va="center",
        fontsize=18,
        color=TEXT,
        fontweight="bold"
    )

    ax.text(
        6.5,
        11.60,
        "Flowchart thuật toán mã hóa và giải mã AES",
        ha="center",
        va="center",
        fontsize=9,
        color=SUBTEXT,
        style="italic"
    )


    # ------------------------------------------------------
    # Khung bên trái
    # ------------------------------------------------------

    left_panel = FancyBboxPatch(
        (0.25, 1.0),
        5.95,
        10.25,
        boxstyle="round,pad=0,rounding_size=0.12",
        linewidth=1.3,
        edgecolor=BLUE_BORDER,
        facecolor=WHITE,
        zorder=0
    )

    ax.add_patch(left_panel)


    # ------------------------------------------------------
    # Khung bên phải
    # ------------------------------------------------------

    right_panel = FancyBboxPatch(
        (6.80, 1.0),
        5.95,
        10.25,
        boxstyle="round,pad=0,rounding_size=0.12",
        linewidth=1.3,
        edgecolor=PURPLE_BORDER,
        facecolor=WHITE,
        zorder=0
    )

    ax.add_patch(right_panel)


    # ------------------------------------------------------
    # Đường giữa
    # ------------------------------------------------------

    ax.plot(
        [6.5, 6.5],
        [1.2, 11.25],
        color="#CBD5E1",
        linewidth=1.2,
        linestyle="--"
    )


    # ------------------------------------------------------
    # ENCRYPTION
    # ------------------------------------------------------

    draw_side(
        ax,
        3.25,
        encryption=True
    )


    # ------------------------------------------------------
    # DECRYPTION
    # ------------------------------------------------------

    draw_side(
        ax,
        9.75,
        encryption=False
    )


    # ------------------------------------------------------
    # LƯU FILE
    # ------------------------------------------------------

    output = "AES_Flowchart_Method.png"

    plt.savefig(
        output,
        dpi=250,
        bbox_inches="tight",
        facecolor=BG
    )

    plt.close(fig)


    print()
    print("=" * 60)
    print("ĐÃ TẠO FLOWCHART AES-128")
    print("=" * 60)
    print()
    print("File:")
    print("  AES_Flowchart_Method.png")
    print()
    print("Encryption:")
    print("  Plaintext")
    print("      ↓")
    print("  State 4×4")
    print("      ↓")
    print("  AddRoundKey[0]")
    print("      ↓")
    print("  Main Round ×9")
    print("      ↓")
    print("  Final Round")
    print("      ↓")
    print("  Ciphertext")
    print()
    print("Decryption:")
    print("  Ciphertext")
    print("      ↓")
    print("  State 4×4")
    print("      ↓")
    print("  AddRoundKey[10]")
    print("      ↓")
    print("  Main Round ×9")
    print("      ↓")
    print("  Final Round")
    print("      ↓")
    print("  Plaintext")
    print()
    print("=" * 60)


# ==========================================================
# CHẠY CHƯƠNG TRÌNH
# ==========================================================

if __name__ == "__main__":
    main()