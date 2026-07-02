#include "Patterns.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>

std::string GetOwnDllDir();

namespace Offsets {
    std::string GetActiveOffset;
    std::string ActorManagerCtorOffset;
    std::string GetGlobalActorOffset;
    std::string AvatarPaimonAppearOffset;
    std::string GetMainCameraOffset;
    std::string GetTransformOffset;
    std::string SetPosOffset;
    std::string CameraGetC2WOffset;
    std::string GetComponent;
    std::string GetText;
    std::string ClockPageOkOffset;
    std::string ClockPageCloseOffset;
    std::string ClockPageFinishOffset;
    std::string ClockPageBackOffset;
    std::string ResinListOffset;
    std::string TouchInputOffset;
    std::string InnerDispatcherOffset;
    std::string EventCameraOffset;
    std::string SetTextOffset;
    std::string SetColorOffset;
    std::string SetFontSizeOffset;
    std::string DamageColorAOffset;
    std::string DamageColorBOffset;
    std::string DamageColor1Offset;
    std::string DamageColor2Offset;
    std::string DamageColor3Offset;
    std::string DamageColor4Offset;

    static std::string ParseOffsetFromJson(const std::string& jsonStr, const std::string& region, const std::string& key, const std::string& fallback) {
        size_t regionStart = jsonStr.find("\"" + region + "\"");
        if (regionStart != std::string::npos) {
            size_t blockStart = jsonStr.find("{", regionStart);
            size_t blockEnd = jsonStr.find("}", blockStart);
            if (blockStart != std::string::npos && blockEnd != std::string::npos) {
                std::string block = jsonStr.substr(blockStart, blockEnd - blockStart);
                std::regex keyRegex("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
                std::smatch match;
                if (std::regex_search(block, match, keyRegex) && match.size() > 1) {
                    return match.str(1);
                }
            }
        }
        return fallback;
    }

    static std::string GetBestOffsetJsonPath() {
        namespace fs = std::filesystem;
        std::string currentDir = GetOwnDllDir();

        fs::path pathLocal = fs::path(currentDir) / "offset.json";
        fs::path pathParent = fs::path(currentDir) / ".." / "offset.json";

        std::error_code ecLocal, ecParent;
        bool existsLocal = fs::exists(pathLocal, ecLocal) && !ecLocal;
        bool existsParent = fs::exists(pathParent, ecParent) && !ecParent;

        if (existsLocal && existsParent) {
            auto timeLocal = fs::last_write_time(pathLocal, ecLocal);
            auto timeParent = fs::last_write_time(pathParent, ecParent);
            if (!ecLocal && !ecParent) {
                return (timeLocal > timeParent) ? pathLocal.string() : pathParent.string();
            }
        }

        if (existsLocal) return pathLocal.string();
        if (existsParent) return pathParent.string();
        return "";
    }

    void InitOffsets(bool isOS) {
        if (isOS) {
            GetActiveOffset = Patterns::OS::GetActiveOffset;
            ActorManagerCtorOffset = Patterns::OS::ActorManagerCtorOffset;
            GetGlobalActorOffset = Patterns::OS::GetGlobalActorOffset;
            AvatarPaimonAppearOffset = Patterns::OS::AvatarPaimonAppearOffset;
            GetMainCameraOffset = Patterns::OS::GetMainCameraOffset;
            GetTransformOffset = Patterns::OS::GetTransformOffset;
            SetPosOffset = Patterns::OS::SetPosOffset;
            CameraGetC2WOffset = Patterns::OS::CameraGetC2WOffset;
            GetComponent = Patterns::OS::GetComponent;
            GetText = Patterns::OS::GetText;
            ClockPageOkOffset = Patterns::OS::ClockPageOkOffset;
            ClockPageCloseOffset = Patterns::OS::ClockPageCloseOffset;
            ClockPageFinishOffset = Patterns::OS::ClockPageFinishOffset;
            ClockPageBackOffset = Patterns::OS::ClockPageBackOffset;
            ResinListOffset = Patterns::OS::ResinListOffset;
            TouchInputOffset = Patterns::OS::TouchInputOffset;
            InnerDispatcherOffset = Patterns::OS::InnerDispatcherOffset;
            EventCameraOffset = Patterns::OS::EventCameraOffset;
            SetTextOffset = Patterns::OS::SetText;
            SetColorOffset = Patterns::OS::SetColor;
            DamageColorAOffset = Patterns::OS::DamageColorA;
            DamageColorBOffset = Patterns::OS::DamageColorB;
            DamageColor1Offset = Patterns::OS::DamageColor1;
            DamageColor2Offset = Patterns::OS::DamageColor2;
            DamageColor3Offset = Patterns::OS::DamageColor3;
            DamageColor4Offset = Patterns::OS::DamageColor4;
            std::cout << "[INFO] Pre-initialized Global (OS) Offsets from hardcode" << std::endl;
        } else {
            GetActiveOffset = Patterns::CN::GetActiveOffset;
            ActorManagerCtorOffset = Patterns::CN::ActorManagerCtorOffset;
            GetGlobalActorOffset = Patterns::CN::GetGlobalActorOffset;
            AvatarPaimonAppearOffset = Patterns::CN::AvatarPaimonAppearOffset;
            GetMainCameraOffset = Patterns::CN::GetMainCameraOffset;
            GetTransformOffset = Patterns::CN::GetTransformOffset;
            SetPosOffset = Patterns::CN::SetPosOffset;
            CameraGetC2WOffset = Patterns::CN::CameraGetC2WOffset;
            GetComponent = Patterns::CN::GetComponent;
            GetText = Patterns::CN::GetText;
            ClockPageOkOffset = Patterns::CN::ClockPageOkOffset;
            ClockPageCloseOffset = Patterns::CN::ClockPageCloseOffset;
            ClockPageFinishOffset = Patterns::CN::ClockPageFinishOffset;
            ClockPageBackOffset = Patterns::CN::ClockPageBackOffset;
            ResinListOffset = Patterns::CN::ResinListOffset;
            TouchInputOffset = Patterns::CN::TouchInputOffset;
            InnerDispatcherOffset = Patterns::CN::InnerDispatcherOffset;
            EventCameraOffset = Patterns::CN::EventCameraOffset;
            SetTextOffset = Patterns::CN::SetText;
            SetColorOffset = Patterns::CN::SetColor;
            DamageColorAOffset = Patterns::CN::DamageColorA;
            DamageColorBOffset = Patterns::CN::DamageColorB;
            DamageColor1Offset = Patterns::CN::DamageColor1;
            DamageColor2Offset = Patterns::CN::DamageColor2;
            DamageColor3Offset = Patterns::CN::DamageColor3;
            DamageColor4Offset = Patterns::CN::DamageColor4;
            std::cout << "[INFO] Pre-initialized China (CN) Offsets from hardcode" << std::endl;
        }

        std::string targetJsonPath = GetBestOffsetJsonPath();

        if (!targetJsonPath.empty()) {
            std::ifstream jsonFile(targetJsonPath);
            if (jsonFile.is_open()) {
                std::stringstream buffer;
                buffer << jsonFile.rdbuf();
                std::string jsonContent = buffer.str();
                std::string region = isOS ? "OS" : "CN";

                std::cout << "[INFO] Found offset.json at " << targetJsonPath << ". Attempting to merge..." << std::endl;

                GetActiveOffset = ParseOffsetFromJson(jsonContent, region, "GetActiveOffset", GetActiveOffset);
                ActorManagerCtorOffset = ParseOffsetFromJson(jsonContent, region, "ActorManagerCtorOffset", ActorManagerCtorOffset);
                GetGlobalActorOffset = ParseOffsetFromJson(jsonContent, region, "GetGlobalActorOffset", GetGlobalActorOffset);
                AvatarPaimonAppearOffset = ParseOffsetFromJson(jsonContent, region, "AvatarPaimonAppearOffset", AvatarPaimonAppearOffset);
                GetMainCameraOffset = ParseOffsetFromJson(jsonContent, region, "GetMainCameraOffset", GetMainCameraOffset);
                GetTransformOffset = ParseOffsetFromJson(jsonContent, region, "GetTransformOffset", GetTransformOffset);
                SetPosOffset = ParseOffsetFromJson(jsonContent, region, "SetPosOffset", SetPosOffset);
                CameraGetC2WOffset = ParseOffsetFromJson(jsonContent, region, "CameraGetC2WOffset", CameraGetC2WOffset);
                GetComponent = ParseOffsetFromJson(jsonContent, region, "GetComponent", GetComponent);
                GetText = ParseOffsetFromJson(jsonContent, region, "GetText", GetText);
                ClockPageOkOffset = ParseOffsetFromJson(jsonContent, region, "ClockPageOkOffset", ClockPageOkOffset);
                ClockPageCloseOffset = ParseOffsetFromJson(jsonContent, region, "ClockPageCloseOffset", ClockPageCloseOffset);
                ClockPageFinishOffset = ParseOffsetFromJson(jsonContent, region, "ClockPageFinishOffset", ClockPageFinishOffset);
                ClockPageBackOffset = ParseOffsetFromJson(jsonContent, region, "ClockPageBackOffset", ClockPageBackOffset);
                ResinListOffset = ParseOffsetFromJson(jsonContent, region, "ResinListOffset", ResinListOffset);
                TouchInputOffset = ParseOffsetFromJson(jsonContent, region, "TouchInput", TouchInputOffset);
                InnerDispatcherOffset = ParseOffsetFromJson(jsonContent, region, "InnerDispatcherOffset", InnerDispatcherOffset);
                EventCameraOffset = ParseOffsetFromJson(jsonContent, region, "EventCamera", EventCameraOffset);
                SetTextOffset = ParseOffsetFromJson(jsonContent, region, "SetTextOffset", SetTextOffset);
                SetColorOffset = ParseOffsetFromJson(jsonContent, region, "SetColorOffset", SetColorOffset);
                DamageColorAOffset = ParseOffsetFromJson(jsonContent, region, "DamageColorAOffset", DamageColorAOffset);
                DamageColorBOffset = ParseOffsetFromJson(jsonContent, region, "DamageColorBOffset", DamageColorBOffset);
                DamageColor1Offset = ParseOffsetFromJson(jsonContent, region, "DamageColor1Offset", DamageColor1Offset);
                DamageColor2Offset = ParseOffsetFromJson(jsonContent, region, "DamageColor2Offset", DamageColor2Offset);
                DamageColor3Offset = ParseOffsetFromJson(jsonContent, region, "DamageColor3Offset", DamageColor3Offset);
                DamageColor4Offset = ParseOffsetFromJson(jsonContent, region, "DamageColor4Offset", DamageColor4Offset);

                std::cout << "[INFO] Offsets initialized. Source logic overridden by local offset.json (Region: " << region << ")" << std::endl;
            } else {
                std::cout << "[INFO] Failed to open offset.json at " << targetJsonPath << ". Proceeding with default hardcoded offsets" << std::endl;
            }
        } else {
            std::cout << "[INFO] No valid offset.json found in Plugins or FuFuPlugin directories. Proceeding with default hardcoded offsets" << std::endl;
        }
    }
}
