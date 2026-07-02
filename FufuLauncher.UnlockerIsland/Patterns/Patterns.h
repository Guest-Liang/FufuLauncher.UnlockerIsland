#pragma once
#include <string>

namespace Patterns {
    inline constexpr const char* GetFrameCount = "E8 ? ? ? ? 85 C0 7E 0E E8 ? ? ? ? 0F 57 C0 F3 0F 2A C0 EB 08";
    inline constexpr const char* SetFrameCount = "E8 ? ? ? ? E8 ? ? ? ? 83 F8 1F 0F 9C 05 ? ? ? ? 48 8B 05";
    inline constexpr const char* ChangeFOV = "40 53 48 83 EC 60 0F 29 74 24 ? 48 8B D9 0F 28 F1 E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 48 8B C8";
    inline constexpr const char* SwitchInputDeviceToTouchScreen = "56 57 48 83 EC ? 48 89 CE 80 3D ? ? ? ? 00 48 8B 05 ? ? ? ? 0F 85 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 48 8B 15 ? ? ? ? E8 ? ? ? ? 48 89 C7 48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 31 D2";
    inline constexpr const char* QuestBanner = "41 57 41 56 56 57 55 53 48 81 EC ? ? ? ? 0F 29 BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 48 89 CE 80 3D ? ? ? ? 00 0F 85 ? ? ? ? 48 8B 96";
    inline constexpr const char* FindGameObject = "40 53 48 83 EC ? 48 89 4C 24 ? 48 8D 54 24 ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B 08 48 85 C9 75 ? 48 8D 48 ? E8 ? ? ? ? 48 8B 4C 24 ? 48 8B D8 48 85 C9 74 ? 48 83 7C 24 ? 00 76";
    inline constexpr const char* SetActive = "E8 ? ? ? ? 48 8B 56 ? 48 85 D2 0F 84 ? ? ? ? 80 3D ? ? ? ? 0 0F 85 ? ? ? ? 48 89 D1 E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 89 C1";
    inline constexpr const char* DamageText = "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 44 0F 29 9C 24 ? ? ? ? 44 0F 29 94 24 ? ? ? ? 44 0F 29 8C 24 ? ? ? ? 44 0F 29 84 24 ? ? ? ? 0F 29 BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 44 89 CF 45 89 C4";
    inline constexpr const char* EventCamera = "41 57 41 56 56 57 55 53 48 83 EC ?? 48 89 D7 48 89 CE 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 48 89 F1 E8 ?? ?? ?? ?? 84 C0 0F 85";
    inline constexpr const char* FindString = "56 48 83 ec 20 48 89 ce e8 ? ? ? ? 48 89 f1 89 c2 48 83 c4 20 5e e9 ? ? ? ? cc cc cc cc";
    inline constexpr const char* CraftPartner = "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 4D 89 ? 4C 89 C6 49 89 D4 49 89 CE";
    inline constexpr const char* CraftEntry = "41 56 56 57 53 48 83 EC 58 49 89 CE 80 3D ? ? ? ? 00 0F 84 ? ? ? ? 80 3D ? ? ? ? 00 48 8B 0D ? ? ? ? 0F 85";
    inline constexpr const char* CheckCanEnter = "56 48 81 ec 80 00 00 00 80 3d ? ? ? ? 00 0f 84 ? ? ? ? 80 3d ? ? ? ? 00";
    inline constexpr const char* OpenTeamPage = "56 57 53 48 83 ec 20 89 cb 80 3d ? ? ? ? 00 74 7a 80 3d ? ? ? ? 00 48 8b 05";
    inline constexpr const char* OpenTeam = "48 83 EC ? 80 3D ? ? ? ? 00 75 ? 48 8B 0D ? ? ? ? 80 B9 ? ? ? ? 00 0F 84 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 84 C0 75";
    inline constexpr const char* DisplayFog = "0F B6 02 88 01 8B 42 04 89 41 04 F3 0F 10 52 ? F3 0F 10 4A ? F3 0F 10 42 ? 8B 42 08";
    inline constexpr const char* PlayerPerspective = "E8 ? ? ? ? 48 8B BE ? ? ? ? 80 3D ? ? ? ? ? 0F 85 ? ? ? ? 80 BE ? ? ? ? ? 74 11";
    inline constexpr const char* SetSyncCount = "E8 ? ? ? ? E8 ? ? ? ? 89 C6 E8 ? ? ? ? 31 C9 89 F2 49 89 C0 E8 ? ? ? ? 48 89 C6 48 8B 0D ? ? ? ? 80 B9 ? ? ? ? ? 74 47 48 8B 3D ? ? ? ? 48 85 DF 74 4C";
    inline constexpr const char* GameUpdate = "55 56 57 53 48 83 EC ? 48 8D 6C 24 ? 48 C7 45 ? ? ? ? ? 48 8B 41 ? 48 85 C0 0F 84 ? ? ? ? 83 78";
    inline constexpr const char* CheckCanOpenMap = "E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 48 8B 45 ?? 48 85 C0 74 ?? 41 8B 17 4C 8B 40 ?? 48 8B 48 ?? FF 50 ?? 84 C0 0F 84 ?? ?? ?? ??";
    inline constexpr const char* GetName = "40 53 48 81 EC ?? ?? ?? ?? 48 8B D9 48 85 C9 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 10 48 8B C8 FF 52 ?? 48 85 C0 0F 85 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ??";
    inline constexpr const char* SetupResinList = "E8 ?? ?? ?? ?? 84 DB 74 ?? 4C 89 F1 E8 ?? ?? ?? ?? 49 8B 86 ?? ?? ?? ?? 48 85 C0 75 ?? E9 ?? ?? ?? ??";
    inline constexpr const char* ClockPageOk = "56 57 55 53 48 83 EC ?? 48 89 CE 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 80 BE ?? ?? ?? ?? 00 74 ??";
    inline constexpr const char* ClockPageClose = "56 57 53 48 83 EC ?? 48 89 CE 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 48 8B 8E ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 83 79 ?? 00 7E ?? 48 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 89 C7 48 8B 40 ?? 85 C0 7E ?? 89 C0 31 DB 66 66 66 66 66 66 2E 0F 1F 84 00 00 00 00 00 89 C0 48 39 C3 0F 83 ?? ?? ?? ?? 48 8B 4C DF ?? 48 85 C9 0F 84 ?? ?? ?? ?? 48 8B 01 0F B7 90";
    inline constexpr const char* GetActive = "E8 ?? ?? ?? ?? 84 C0 74 ?? 48 89 F1 E8 ?? ?? ?? ?? 48 8B 4E ?? 48 85 C9 0F 84 ?? ?? ?? ?? 80 79 ?? ?? 0F 94 C1 08 C1";
    inline constexpr const char* ActorManagerCtor = "E8 ?? ?? ?? ?? 48 85 F6 0F 84 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 89 F1 48 8B 55 ?? 49 89 D8 E8 ?? ?? ?? ?? EB ??";
    inline constexpr const char* StringNew = "56 48 83 EC 20 48 85 C9 74 ? 48 89 CE E8 ? ? ? ? 48 89 F1 89 C2";
    inline constexpr const char* ShowDialog = "41 57 41 56 56 57 55 53 48 83 EC 28 4D 89 CF 4C 89 C7 48 89 D5 48 89 CB";
    inline constexpr const char* SetUID = "56 57 48 83 EC 28 89 D7 48 89 CE 80 3D ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 89 BE ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 80 B9 ?? ?? ?? ?? 00 0F 84";
    inline constexpr const char* BuildCmdBuffers = "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC 48 02 00 00 48 89 CE 0F 57 C0 0F 29 84 24 50 01 00 00 0F 29 84 24 40 01 00 00 0F 29 84 24 30 01 00";
    inline constexpr const char* CameraUpdateView = "56 48 83 EC 40 0F 29 7C 24 30 0F 29 74 24 20 48 89 CE F3 0F 10 71 70 F3 0F 10 79 78 F3 0F 5C F7 F3 0F 59 B1 80 00 00 00 E8 ?";
    inline constexpr const char* CameraStateBlenderTick = "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC 38 0D 00 00 44 0F 29 84 24 20 0D 00 00";
    inline constexpr const char* UnderwaterMaskPreMain = "41 56 56 57 55 53 48 81 EC F0 04 00 00";
    inline constexpr const char* UnderwaterMaskMain = "41 57 41 56 56 57 53 48 81 EC D0 04 00 00 48 89 CE";
    inline constexpr const char* UnderwaterMaskPostMain = "41 56 56 57 55 53 48 81 EC E0 00 00 00 48 89 CE 80 3D ? ? ? ? ? 75 ? 48 8B 86 ? ? ? ? 48 85 C0";
    inline constexpr const char* UnderwaterMaskClear = "56 57 48 83 EC 28 48 89 CE 80 3D ? ? ? ? ? 0F 85 ? ? ? ? 80 3D ? ? ? ? ? 0F 85 ? ? ? ? 48 8D BE ? ? ? ? 80 3D";
    
    namespace Helper {
        inline constexpr const char* InnerDispatcher_1 = "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC E8 00 00 00 4C 89 CB 4C 89 C7 48 89 D5 48 89 CA";
        inline constexpr const char* InnerDispatcher_2 = "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC E8 00 00 00 4C 89 CB 4C 89 C7";
        inline constexpr const char* InnerDispatcher_3 = "41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? 00 00 00 4C 89 CB 4C 89 C7 48 89 D5 48 89 CA";
    }

    namespace CN {
        inline constexpr const char* GetActiveOffset = "173a9680";
        inline constexpr const char* ActorManagerCtorOffset = "e3e40d0";
        inline constexpr const char* GetGlobalActorOffset = "e3e69f0";
        inline constexpr const char* AvatarPaimonAppearOffset = "11a655e0";
        inline constexpr const char* GetMainCameraOffset = "173ba100";
        inline constexpr const char* GetTransformOffset = "173caae0";
        inline constexpr const char* SetPosOffset = "173c4140";
        inline constexpr const char* CameraGetC2WOffset = "173b95f0";
        inline constexpr const char* GetComponent = "173cab60";
        inline constexpr const char* GetText = "174a92e0";
        inline constexpr const char* ClockPageOkOffset = "11919E90";
        inline constexpr const char* ClockPageCloseOffset = "ECF7DC0";
        inline constexpr const char* ClockPageFinishOffset = "11919A50";
        inline constexpr const char* ClockPageBackOffset = "119172C0";
        inline constexpr const char* ResinListOffset = "220";
        inline constexpr const char* TouchInputOffset = "8D00130";
        inline constexpr const char* InnerDispatcherOffset = "105C0E80";
        inline constexpr const char* EventCameraOffset = "0";
        inline constexpr const char* SetText = "174a92f0";
        inline constexpr const char* SetColor = "174a5020";
        inline constexpr const char* DamageColorA = "11b0ace0";
        inline constexpr const char* DamageColorB = "11b08a60";
        inline constexpr const char* DamageColor1 = "11b08920";
        inline constexpr const char* DamageColor2 = "11b08620";
        inline constexpr const char* DamageColor3 = "11b088b0";
        inline constexpr const char* DamageColor4 = "11b085b0";
    }

    namespace OS {
        inline constexpr const char* GetActiveOffset = "173a1ed0";
        inline constexpr const char* ActorManagerCtorOffset = "e3cc5e0";
        inline constexpr const char* GetGlobalActorOffset = "e3dae10";
        inline constexpr const char* AvatarPaimonAppearOffset = "11a6d300";
        inline constexpr const char* GetMainCameraOffset = "173b2950";
        inline constexpr const char* GetTransformOffset = "173c3330";
        inline constexpr const char* SetPosOffset = "173bc990";
        inline constexpr const char* CameraGetC2WOffset = "173b1e40";
        inline constexpr const char* GetComponent = "173c33b0";
        inline constexpr const char* GetText = "174a1b70";
        inline constexpr const char* ClockPageOkOffset = "11933430";
        inline constexpr const char* ClockPageCloseOffset = "ED0A3E0";
        inline constexpr const char* ClockPageFinishOffset = "119315A0";
        inline constexpr const char* ClockPageBackOffset = "11930990";
        inline constexpr const char* ResinListOffset = "230";
        inline constexpr const char* TouchInputOffset = "8CEAB90";
        inline constexpr const char* InnerDispatcherOffset = "105CAE70";
        inline constexpr const char* EventCameraOffset = "0";
        inline constexpr const char* SetText = "174a1b80";
        inline constexpr const char* SetColor = "1749d8a0";
        inline constexpr const char* DamageColorA = "11b10950";
        inline constexpr const char* DamageColorB = "11b11c80";
        inline constexpr const char* DamageColor1 = "11b10810";
        inline constexpr const char* DamageColor2 = "11b0fa40";
        inline constexpr const char* DamageColor3 = "11b107a0";
        inline constexpr const char* DamageColor4 = "11b0f9d0";
    }
}

namespace GameStrings {
    inline constexpr const char* SynthesisPage = "SynthesisPage";
    inline constexpr const char* QuestBannerPath = "Canvas/Pages/InLevelMapPage/GrpMap/GrpPointTips/Layout/QuestBanner";
    inline constexpr const char* PaimonPath = "/EntityRoot/OtherGadgetRoot/NPC_Guide_Paimon(Clone)";
    inline constexpr const char* BeydPaimonPath = "/EntityRoot/OtherGadgetRoot/Beyd_NPC_Kanban_Paimon(Clone)";
    inline constexpr const char* DivePaimonPath = "/EntityRoot/OtherGadgetRoot/NPC_Guide_Paimon_Dive(Clone)";
    inline constexpr const char* ProfileLayerPath = "/Canvas/Pages/PlayerProfilePage";
    inline constexpr const char* UIDPathMain = "/Canvas/Pages/PlayerProfilePage/GrpProfile/Right/GrpPlayerCard/UID";
    inline constexpr const char* UIDPathWatermark = "/BetaWatermarkCanvas(Clone)/Panel/TxtUID";
}

namespace Offsets {
    extern std::string GetActiveOffset;
    extern std::string ActorManagerCtorOffset;
    extern std::string GetGlobalActorOffset;
    extern std::string AvatarPaimonAppearOffset;
    extern std::string GetMainCameraOffset;
    extern std::string GetTransformOffset;
    extern std::string SetPosOffset;
    extern std::string CameraGetC2WOffset;
    extern std::string GetComponent;
    extern std::string GetText;
    extern std::string ClockPageOkOffset;
    extern std::string ClockPageCloseOffset;
    extern std::string ClockPageFinishOffset;
    extern std::string ClockPageBackOffset;
    extern std::string ResinListOffset;
    extern std::string TouchInputOffset;
    extern std::string InnerDispatcherOffset;
    extern std::string EventCameraOffset;
    extern std::string SetTextOffset;
    extern std::string SetColorOffset;
    extern std::string SetFontSizeOffset;
    extern std::string DamageColorAOffset;
    extern std::string DamageColorBOffset;
    extern std::string DamageColor1Offset;
    extern std::string DamageColor2Offset;
    extern std::string DamageColor3Offset;
    extern std::string DamageColor4Offset;

    void InitOffsets(bool isOS);
}
