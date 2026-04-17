#pragma once

namespace Hooks {
    bool Init();
    void Uninit();
    
    bool IsGameUpdateInit();
    void RequestOpenCraft();
    void TriggerReloadPopup();
    void UpdateVisuals();

    uint32_t GetCurrentUID();
}