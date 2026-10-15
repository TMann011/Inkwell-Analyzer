#include "theme.h"

namespace Inkwell {

ThemeStyle g_Style;

void ApplyThemePreset(ThemePreset preset) {
    g_Style.currentPreset = preset;

    // Fixed Status indicators
    g_Style.SuccessColor = ImVec4(0.20f, 0.85f, 0.45f, 1.00f);
    g_Style.WarningColor = ImVec4(0.95f, 0.70f, 0.20f, 1.00f);
    g_Style.ErrorColor   = ImVec4(0.95f, 0.25f, 0.30f, 1.00f);
    g_Style.KernelColor  = ImVec4(0.40f, 0.80f, 1.00f, 1.00f);
    g_Style.MemoryColor  = ImVec4(0.85f, 0.45f, 0.95f, 1.00f);

    switch (preset) {
    case ThemePreset::PurpleBlack:
        g_Style.AccentColor   = ImVec4(0.60f, 0.30f, 0.98f, 1.00f); // Neon Violet
        g_Style.AccentHovered = ImVec4(0.70f, 0.40f, 1.00f, 0.90f);
        g_Style.AccentActive  = ImVec4(0.78f, 0.48f, 1.00f, 1.00f);
        g_Style.Background    = ImVec4(0.04f, 0.03f, 0.06f, 0.98f); // Dark Pitch Glass
        g_Style.PanelBg       = ImVec4(0.08f, 0.06f, 0.12f, 0.88f); // Dark Violet Card
        g_Style.PanelAlt      = ImVec4(0.12f, 0.09f, 0.18f, 0.65f);
        g_Style.Border        = ImVec4(0.26f, 0.16f, 0.40f, 0.60f);
        g_Style.TextPrimary   = ImVec4(0.96f, 0.95f, 0.98f, 1.00f);
        g_Style.TextSecondary = ImVec4(0.68f, 0.60f, 0.78f, 1.00f);
        g_Style.TextMuted     = ImVec4(0.44f, 0.36f, 0.52f, 1.00f);
        break;

    case ThemePreset::ElectricIndigo:
        g_Style.AccentColor   = ImVec4(0.35f, 0.50f, 0.98f, 1.00f); // Electric Blue/Indigo
        g_Style.AccentHovered = ImVec4(0.42f, 0.58f, 1.00f, 0.90f);
        g_Style.AccentActive  = ImVec4(0.50f, 0.65f, 1.00f, 1.00f);
        g_Style.Background    = ImVec4(0.04f, 0.05f, 0.07f, 0.98f);
        g_Style.PanelBg       = ImVec4(0.08f, 0.10f, 0.14f, 0.88f);
        g_Style.PanelAlt      = ImVec4(0.11f, 0.14f, 0.19f, 0.65f);
        g_Style.Border        = ImVec4(0.18f, 0.22f, 0.32f, 0.60f);
        g_Style.TextPrimary   = ImVec4(0.95f, 0.96f, 0.98f, 1.00f);
        g_Style.TextSecondary = ImVec4(0.60f, 0.65f, 0.75f, 1.00f);
        g_Style.TextMuted     = ImVec4(0.38f, 0.42f, 0.50f, 1.00f);
        break;

    case ThemePreset::CyberEmerald:
        g_Style.AccentColor   = ImVec4(0.06f, 0.78f, 0.52f, 1.00f); // Neon Emerald
        g_Style.AccentHovered = ImVec4(0.12f, 0.88f, 0.60f, 0.90f);
        g_Style.AccentActive  = ImVec4(0.18f, 0.96f, 0.68f, 1.00f);
        g_Style.Background    = ImVec4(0.03f, 0.05f, 0.04f, 0.98f);
        g_Style.PanelBg       = ImVec4(0.06f, 0.11f, 0.09f, 0.88f);
        g_Style.PanelAlt      = ImVec4(0.09f, 0.15f, 0.12f, 0.65f);
        g_Style.Border        = ImVec4(0.14f, 0.30f, 0.24f, 0.60f);
        g_Style.TextPrimary   = ImVec4(0.93f, 0.98f, 0.95f, 1.00f);
        g_Style.TextSecondary = ImVec4(0.55f, 0.75f, 0.65f, 1.00f);
        g_Style.TextMuted     = ImVec4(0.34f, 0.50f, 0.42f, 1.00f);
        break;

    case ThemePreset::CrimsonBlood:
        g_Style.AccentColor   = ImVec4(0.88f, 0.22f, 0.28f, 1.00f); // Crimson
        g_Style.AccentHovered = ImVec4(0.96f, 0.28f, 0.34f, 0.90f);
        g_Style.AccentActive  = ImVec4(1.00f, 0.35f, 0.40f, 1.00f);
        g_Style.Background    = ImVec4(0.06f, 0.03f, 0.04f, 0.98f);
        g_Style.PanelBg       = ImVec4(0.12f, 0.06f, 0.08f, 0.88f);
        g_Style.PanelAlt      = ImVec4(0.17f, 0.09f, 0.11f, 0.65f);
        g_Style.Border        = ImVec4(0.35f, 0.15f, 0.20f, 0.60f);
        g_Style.TextPrimary   = ImVec4(0.98f, 0.94f, 0.95f, 1.00f);
        g_Style.TextSecondary = ImVec4(0.74f, 0.55f, 0.58f, 1.00f);
        g_Style.TextMuted     = ImVec4(0.50f, 0.34f, 0.38f, 1.00f);
        break;

    case ThemePreset::SlateMonochrome:
    default:
        g_Style.AccentColor   = ImVec4(0.65f, 0.68f, 0.75f, 1.00f); // Cold Titanium
        g_Style.AccentHovered = ImVec4(0.75f, 0.78f, 0.85f, 0.90f);
        g_Style.AccentActive  = ImVec4(0.85f, 0.88f, 0.95f, 1.00f);
        g_Style.Background    = ImVec4(0.05f, 0.05f, 0.06f, 0.98f);
        g_Style.PanelBg       = ImVec4(0.10f, 0.10f, 0.12f, 0.88f);
        g_Style.PanelAlt      = ImVec4(0.14f, 0.14f, 0.17f, 0.65f);
        g_Style.Border        = ImVec4(0.24f, 0.24f, 0.28f, 0.60f);
        g_Style.TextPrimary   = ImVec4(0.95f, 0.95f, 0.96f, 1.00f);
        g_Style.TextSecondary = ImVec4(0.65f, 0.65f, 0.68f, 1.00f);
        g_Style.TextMuted     = ImVec4(0.40f, 0.40f, 0.44f, 1.00f);
        break;
    }

    ImGuiStyle& style = ImGui::GetStyle();
    style.Colors[ImGuiCol_WindowBg]             = g_Style.Background;
    style.Colors[ImGuiCol_ChildBg]              = g_Style.PanelBg;
    style.Colors[ImGuiCol_PopupBg]              = g_Style.PanelBg;
    style.Colors[ImGuiCol_Border]               = g_Style.Border;
    style.Colors[ImGuiCol_BorderShadow]         = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    style.Colors[ImGuiCol_FrameBg]              = g_Style.PanelAlt;
    style.Colors[ImGuiCol_FrameBgHovered]       = ImVec4(g_Style.PanelAlt.x * 1.3f, g_Style.PanelAlt.y * 1.3f, g_Style.PanelAlt.z * 1.3f, 0.85f);
    style.Colors[ImGuiCol_FrameBgActive]        = g_Style.AccentActive;
    style.Colors[ImGuiCol_TitleBg]              = g_Style.Background;
    style.Colors[ImGuiCol_TitleBgActive]        = g_Style.Background;
    style.Colors[ImGuiCol_TitleBgCollapsed]     = g_Style.Background;
    style.Colors[ImGuiCol_MenuBarBg]            = g_Style.PanelBg;
    style.Colors[ImGuiCol_ScrollbarBg]          = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    style.Colors[ImGuiCol_ScrollbarGrab]        = g_Style.PanelAlt;
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = g_Style.Border;
    style.Colors[ImGuiCol_ScrollbarGrabActive]  = g_Style.AccentColor;
    style.Colors[ImGuiCol_CheckMark]            = g_Style.AccentColor;
    style.Colors[ImGuiCol_SliderGrab]           = g_Style.AccentColor;
    style.Colors[ImGuiCol_SliderGrabActive]     = g_Style.AccentActive;
    style.Colors[ImGuiCol_Button]               = g_Style.PanelAlt;
    style.Colors[ImGuiCol_ButtonHovered]        = g_Style.AccentHovered;
    style.Colors[ImGuiCol_ButtonActive]         = g_Style.AccentActive;
    style.Colors[ImGuiCol_Header]               = g_Style.PanelAlt;
    style.Colors[ImGuiCol_HeaderHovered]        = g_Style.AccentHovered;
    style.Colors[ImGuiCol_HeaderActive]         = g_Style.AccentActive;
    style.Colors[ImGuiCol_Separator]            = g_Style.Border;
    style.Colors[ImGuiCol_SeparatorHovered]     = g_Style.AccentHovered;
    style.Colors[ImGuiCol_SeparatorActive]      = g_Style.AccentActive;
    style.Colors[ImGuiCol_ResizeGrip]           = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    style.Colors[ImGuiCol_ResizeGripHovered]    = g_Style.AccentHovered;
    style.Colors[ImGuiCol_ResizeGripActive]     = g_Style.AccentActive;
    style.Colors[ImGuiCol_Tab]                  = g_Style.PanelBg;
    style.Colors[ImGuiCol_TabHovered]           = g_Style.AccentHovered;
    style.Colors[ImGuiCol_TabActive]            = g_Style.PanelAlt;
    style.Colors[ImGuiCol_TabUnfocused]         = g_Style.PanelBg;
    style.Colors[ImGuiCol_TabUnfocusedActive]   = g_Style.PanelAlt;
    style.Colors[ImGuiCol_Text]                 = g_Style.TextPrimary;
    style.Colors[ImGuiCol_TextDisabled]         = g_Style.TextMuted;

    // Window Metrics
    style.WindowRounding    = 10.0f;
    style.ChildRounding     = 8.0f;
    style.FrameRounding     = 6.0f;
    style.PopupRounding     = 8.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding      = 4.0f;
    style.TabRounding       = 6.0f;

    style.WindowBorderSize  = 1.0f;
    style.FrameBorderSize   = 1.0f;
    style.PopupBorderSize   = 1.0f;

    style.WindowPadding     = ImVec2(16.0f, 16.0f);
    style.FramePadding      = ImVec2(10.0f, 6.0f);
    style.ItemSpacing       = ImVec2(10.0f, 8.0f);
    style.ItemInnerSpacing  = ImVec2(6.0f, 6.0f);
    style.ScrollbarSize     = 10.0f;
}

void PushCardStyle() {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, g_Style.PanelBg);
    ImGui::PushStyleColor(ImGuiCol_Border, g_Style.Border);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 12.0f));
}

void PopCardStyle() {
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
}

} // namespace Inkwell
