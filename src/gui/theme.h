#pragma once

#include "../imgui/imgui.h"

namespace Inkwell {

enum class ThemePreset {
    PurpleBlack = 0,    // Signature Inkwell Violet
    ElectricIndigo,     // Cyan / Electric Indigo
    CyberEmerald,       // Neon Emerald Matrix
    CrimsonBlood,       // High-Contrast Red
    SlateMonochrome     // Minimalist Deep Slate
};

struct ThemeStyle {
    ThemePreset currentPreset = ThemePreset::PurpleBlack;

    ImVec4 AccentColor;
    ImVec4 AccentHovered;
    ImVec4 AccentActive;
    ImVec4 Background;
    ImVec4 PanelBg;
    ImVec4 PanelAlt;
    ImVec4 Border;
    ImVec4 TextPrimary;
    ImVec4 TextSecondary;
    ImVec4 TextMuted;

    // Status Colors
    ImVec4 SuccessColor;
    ImVec4 WarningColor;
    ImVec4 ErrorColor;
    ImVec4 KernelColor;
    ImVec4 MemoryColor;
};

extern ThemeStyle g_Style;

void ApplyThemePreset(ThemePreset preset);
void PushCardStyle();
void PopCardStyle();

} // namespace Inkwell
