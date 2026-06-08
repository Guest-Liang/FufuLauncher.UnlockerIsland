## 仅供学习交流

* 使用的特征码，理论上在原神7.0版本之前都可用，且无需每个版本更新
* 目前有部分功能存在问题，例如对于HSR共用的适配还未完善

如需要稳定为先，请使用Dev分支

## Architecture

```
FufuLauncher.UnlockerIsland/
├── Core/
│   ├── dllmain.cpp
│   ├── Hooks.cpp/h
│   ├── SharedState.cpp/h
│   └── Utils.h
├── Config/
│   └── Config.cpp/h
├── Patterns/
│   └── Patterns.cpp/h
├── Scanner/
│   └── Scanner.cpp/h
├── Visual/
│   └── Visual.cpp/h
├── FreeCam/
│   └── FreeCam.cpp/h
├── HideUI/
│   └── HideUI.cpp/h
├── CustomUID/
│   └── CustomUID.cpp/h
├── Paimon/
│   └── Paimon.cpp/h
├── Automation/
│   └── Automation.cpp/h
├── GamepadHotSwitch/
│   └── GamepadHotSwitch.cpp/h
├── RainbowDamage/
│   └── RainbowDamage.cpp/h
├── Network/
│   └── Network.cpp/h
├── MinHook/
│   ├── MinHook.h
│   └── libMinHook.x64.lib
└── il2cpp/
    ├── Il2CppObject.h
    ├── Il2CppArray.h
    └── Il2CppList.h
```
