// Copyright (c) 2019 Centre Tecnologic de Telecomunicacions de Catalunya (CTTC)
// Modified in 2026 from the 5G-LENA example cttc-nr-demo.cc.
// SPDX-License-Identifier: GPL-2.0-only

#include "ns3/antenna-module.h"
#include "ns3/applications-module.h"
#include "ns3/buildings-module.h"
#include "ns3/config-store-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-module.h"

#include <cctype>
#include <cmath>
#include <filesystem>
#include <map>
#include <set>
#include <vector>
#include <iostream>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Rise2q");

int
main(int argc, char* argv[])
{
    uint16_t numLegit = 10;

    uint32_t numTags = 0;
    double tagIntervalS = 3600.0;
    uint32_t tagPacketSize = 64;

    bool dmgnbat = false;

    bool pcgnbat = false;

    uint16_t pcClusters = 2;
    bool csgnbat = false;

    int attackers = -1;

    bool logging = false;

    uint32_t packetSizeAttack = 1400;

    const uint32_t legitProfilePacketSize[3] = {512, 20, 256};
    const double legitProfileIntervalMs[3] = {33.032, 2.0, 200.0};

    double totalAttackRatePps = 101010.0;

    double fpProbeMbps = 0.0;

    Time legitStartTime = Seconds(1.0);
    Time attackStartTime = Seconds(100.0);
    Time simTime = Seconds(150.0);

    uint16_t numerologyBwp1 = 1;
    double centralFrequencyBand1 = 3.5e9;
    double bandwidthBand1 = 20e6;
    double totalTxPower = 35;

    double gnbHeight = 10.0;
    double ueHeight = 1.5;
    double ueMinRadius = 50.0;
    double ueMaxRadius = 200.0;

    double ueTxPowerDbm = -1.0;

    std::string outputDir = "./txt-v2";

    std::string quarantine = "none";
    double quarantineFraction = 0.2;

    int quarantineMcs = -1;

    uint16_t falsePositives = 0;

    std::string scheduler = "";

    bool flushOnQuarantine = false;

    uint32_t rlcBufferKB = 10 * 1024;

    double detectionTime = 101.05;

    std::string backhaulRate = "";

    CommandLine cmd(__FILE__);
    cmd.AddValue("numLegit", "Legitimate IoT devices (5 or 10)", numLegit);
    cmd.AddValue("numTags", "Background Smart Tag devices (0 disables them)", numTags);
    cmd.AddValue("tagIntervalS", "Smart Tag message interval (s)", tagIntervalS);
    cmd.AddValue("tagPacketSize", "Smart Tag message size (bytes)", tagPacketSize);
    cmd.AddValue("dmgnbat",
                 "Distributed topology: attackers in consecutive blocks from gNB 0",
                 dmgnbat);
    cmd.AddValue("csgnbat", "Concentrated topology: all attackers on gNB 0", csgnbat);
    cmd.AddValue("pcgnbat",
                 "Partially concentrated topology: attackers on --pcClusters adjacent gNBs",
                 pcgnbat);
    cmd.AddValue("pcClusters",
                 "gNBs used by the partially concentrated topology (2-4)",
                 pcClusters);
    cmd.AddValue("logging", "Enable UDP and PDCP logs", logging);
    cmd.AddValue("attackers", "Attacking devices (2-20); if omitted, runs 2 to 10", attackers);
    cmd.AddValue("packetSizeAttack", "Attack packet size (bytes)", packetSizeAttack);
    cmd.AddValue("totalAttackRatePps",
                 "Total attack rate (packets/s), split equally among the attackers",
                 totalAttackRatePps);
    cmd.AddValue("simTime", "Simulation time", simTime);
    cmd.AddValue("centralFrequencyBand1", "Central frequency (Hz)", centralFrequencyBand1);
    cmd.AddValue("bandwidthBand1", "Bandwidth (Hz)", bandwidthBand1);
    cmd.AddValue("numerologyBwp1", "Numerology", numerologyBwp1);
    cmd.AddValue("outputDir", "Output directory", outputDir);
    cmd.AddValue("quarantine",
                 "Quarantine mode: none, sliced (control), static or switch",
                 quarantine);
    cmd.AddValue("quarantineFraction",
                 "Bandwidth fraction of the quarantine BWP, in (0, 0.5]",
                 quarantineFraction);
    cmd.AddValue("backhaulRate",
                 "Backhaul (S1-U) rate, e.g. 20Mbps; empty keeps the ns-3 default",
                 backhaulRate);
    cmd.AddValue("flushOnQuarantine", "Not supported; use --rlcBufferKB", flushOnQuarantine);
    cmd.AddValue("rlcBufferKB", "RLC UM buffer per bearer (KiB)", rlcBufferKB);
    cmd.AddValue("ueTxPowerDbm", "UE transmit power (dBm); -1 keeps 2 dBm", ueTxPowerDbm);
    cmd.AddValue("scheduler", "MAC scheduler TypeId; empty keeps the 5G-LENA default", scheduler);
    cmd.AddValue("fpProbeMbps",
                 "Fixed false-positive rate (Mbps); 0 keeps the profiles",
                 fpProbeMbps);
    cmd.AddValue("falsePositives",
                 "Legitimate devices quarantined by mistake (static or switch only)",
                 falsePositives);
    cmd.AddValue("quarantineMcs",
                 "Fixed quarantine MCS (0-28); -1 keeps link adaptation",
                 quarantineMcs);
    cmd.AddValue("detectionTime", "Quarantine time in switch mode (s)", detectionTime);
    cmd.Parse(argc, argv);

    if ((dmgnbat ? 1 : 0) + (pcgnbat ? 1 : 0) + (csgnbat ? 1 : 0) != 1)
    {
        std::cerr << "ERROR: you must choose exactly one topology mode.\n"
                  << "  --dmgnbat  Distributed Multi-gNB Attack Topology (attackers in consecutive blocks from gNB 0)\n"
                  << "  --pcgnbat  Partially Concentrated gNB Attack Topology (attackers clustered on a few gNBs)\n"
                  << "  --csgnbat  Concentrated Single-gNB Attack Topology (attackers on one targeted gNB)\n"
                  << "Pass exactly one of the three.\n"
                  << "Example: ./ns3 run \"rise-2q --dmgnbat\"\n";
        return 1;
    }

    const uint16_t kNumGnb = 5;
    if (pcgnbat && (pcClusters < 2 || pcClusters >= kNumGnb))
    {
        std::cerr << "ERROR: --pcClusters must be between 2 and " << (kNumGnb - 1)
                  << " for PCgNBAT (got " << pcClusters << ").\n";
        return 1;
    }

    if (pcgnbat)
    {
        uint16_t smallestN = (attackers != -1) ? static_cast<uint16_t>(attackers) : 2;
        if (smallestN < pcClusters)
        {
            std::cerr << "ERROR: PCgNBAT with --pcClusters=" << pcClusters
                      << " needs at least " << pcClusters << " attackers, but the smallest "
                      << "count to run is " << smallestN << ".\n"
                      << "Increase --attackers or reduce --pcClusters.\n";
            return 1;
        }
    }

    if (attackers != -1 && (attackers < 2 || attackers > 20))
    {
        std::cerr << "ERROR: --attackers must be between 2 and 20 inclusive (got " << attackers
                  << ").\n"
                  << "Omit --attackers entirely to run the full 2-10 sweep instead.\n"
                  << "Example: ./ns3 run \"rise-2q --dmgnbat --attackers=5\"\n";
        return 1;
    }

    if (quarantine != "none" && quarantine != "sliced" && quarantine != "static" &&
        quarantine != "switch")
    {
        std::cerr << "ERROR: --quarantine must be none, sliced, static or switch (got "
                  << quarantine
                  << ").\n";
        return 1;
    }
    TypeId schedulerTid;
    if (!scheduler.empty() && !TypeId::LookupByNameFailSafe(scheduler, &schedulerTid))
    {
        std::cerr << "ERROR: unknown --scheduler " << scheduler
                  << " (example: ns3::NrMacSchedulerOfdmaRR).\n";
        return 1;
    }
    if (fpProbeMbps < 0.0 || fpProbeMbps > 100.0)
    {
        std::cerr << "ERROR: --fpProbeMbps must be between 0 and 100 (got " << fpProbeMbps
                  << ").\n";
        return 1;
    }
    if (falsePositives > numLegit)
    {
        std::cerr << "ERROR: --falsePositives cannot exceed the number of legitimate devices ("
                  << numLegit << ").\n";
        return 1;
    }
    if (flushOnQuarantine)
    {
        std::cerr << "ERROR: --flushOnQuarantine is not supported. Releasing a dedicated "
                     "bearer during the simulation is not implemented end to end in "
                     "5G-LENA v2.6.y (it fails in the gNB component carrier manager, the gNB "
                     "MAC and the UE component carrier manager). Use --rlcBufferKB to limit "
                     "the traffic a device queues before detection.\n";
        return 1;
    }
    if (numTags > 5000 || tagIntervalS <= 0.0 || tagPacketSize < 12 || tagPacketSize > 1400)
    {
        std::cerr << "ERROR: --numTags must be at most 5000, --tagIntervalS positive and "
                     "--tagPacketSize between 12 and 1400 bytes.\n";
        return 1;
    }
    if (rlcBufferKB == 0)
    {
        std::cerr << "ERROR: --rlcBufferKB must be greater than 0.\n";
        return 1;
    }
    if (falsePositives > 0 && quarantine != "static" && quarantine != "switch")
    {
        std::cerr << "ERROR: --falsePositives needs --quarantine=static or switch.\n";
        return 1;
    }
    if (quarantineMcs < -1 || quarantineMcs > 28)
    {
        std::cerr << "ERROR: --quarantineMcs must be -1 (link adaptation) or 0-28 (got "
                  << quarantineMcs << ").\n";
        return 1;
    }
    if (quarantine == "none" && quarantineMcs >= 0)
    {
        std::cerr << "ERROR: --quarantineMcs needs a quarantine mode (sliced, static or "
                     "switch).\n";
        return 1;
    }
    if (quarantine != "none" && (quarantineFraction <= 0.0 || quarantineFraction > 0.5))
    {
        std::cerr << "ERROR: --quarantineFraction must be in (0, 0.5] (got " << quarantineFraction
                  << ").\n";
        return 1;
    }
    if (quarantine == "switch" && (detectionTime <= attackStartTime.GetSeconds() ||
                                   detectionTime >= simTime.GetSeconds()))
    {
        std::cerr << "ERROR: --detectionTime must lie strictly between the attack start ("
                  << attackStartTime.GetSeconds() << " s) and the end of the simulation ("
                  << simTime.GetSeconds() << " s).\n";
        return 1;
    }

    NS_ABORT_IF(centralFrequencyBand1 < 0.5e9 || centralFrequencyBand1 > 100e9);

    const bool useQuarantine = (quarantine != "none");
    double bwNormal = bandwidthBand1;
    double bwQuarantine = 0.0;
    double fcNormal = centralFrequencyBand1;
    double fcQuarantine = 0.0;
    if (useQuarantine)
    {
        const double rbWidth = 12.0 * 15e3 * (1 << numerologyBwp1);
        auto quantize = [rbWidth](double bw) { return std::floor(bw / rbWidth) * rbWidth; };
        bwQuarantine = quantize(quarantineFraction * bandwidthBand1);
        bwNormal = quantize(bandwidthBand1 - bwQuarantine);
        NS_ABORT_MSG_IF(bwQuarantine <= 0.0 || bwNormal <= 0.0,
                        "quarantineFraction too small or too large for this bandwidth");
        const double bandStart = centralFrequencyBand1 - bandwidthBand1 / 2.0;
        fcNormal = bandStart + bwNormal / 2.0;
        fcQuarantine = bandStart + bwNormal + bwQuarantine / 2.0;

        std::cout << "Quarantine slicing: mode=" << quarantine << ", normal BWP "
                  << bwNormal / 1e6 << " MHz (" << bwNormal / rbWidth << " RBs) at "
                  << fcNormal / 1e9 << " GHz, quarantine BWP " << bwQuarantine / 1e6 << " MHz ("
                  << bwQuarantine / rbWidth << " RBs) at " << fcQuarantine / 1e9 << " GHz";
        if (quarantine == "switch")
        {
            std::cout << ", detection at " << detectionTime << " s";
        }
        if (quarantineMcs >= 0)
        {
            std::cout << ", quarantine uplink MCS fixed at " << quarantineMcs;
        }
        std::cout << std::endl;
    }

    if (logging)
    {
        LogComponentEnable("UdpClient", LOG_LEVEL_INFO);
        LogComponentEnable("UdpServer", LOG_LEVEL_INFO);
        LogComponentEnable("LtePdcp", LOG_LEVEL_INFO);
    }

    Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(rlcBufferKB * 1024));

    std::string pcapDir = "pcaps-v2";
    if (!std::filesystem::exists(pcapDir))
    {
        std::filesystem::create_directories(pcapDir);
    }
    if (!std::filesystem::exists(outputDir))
    {
        std::filesystem::create_directories(outputDir);
    }

    const std::vector<uint16_t> attackerCounts =
        (attackers == -1)
            ? std::vector<uint16_t>{2, 3, 4, 5, 6, 7, 8, 9, 10}
            : std::vector<uint16_t>{static_cast<uint16_t>(attackers)};

    const uint16_t numGnb = 5;
    NS_ABORT_IF(numLegit % numGnb != 0);
    const uint16_t numLegitPerGnb = numLegit / numGnb;
    NS_ABORT_IF(numLegitPerGnb > 2);

    std::vector<Vector> gnbCenters;
    for (uint16_t g = 0; g < numGnb; ++g)
    {
        gnbCenters.push_back(Vector(g * 1000.0, 0.0, gnbHeight));
    }

    const double legitRadius = ueMinRadius + 0.25 * (ueMaxRadius - ueMinRadius);
    const double attackerRadius = ueMinRadius + 0.75 * (ueMaxRadius - ueMinRadius);

    std::vector<Vector> legitPositions;
    for (uint16_t g = 0; g < numGnb; ++g)
    {
        for (uint16_t k = 0; k < numLegitPerGnb; ++k)
        {
            double theta = (k == 0) ? 0.0 : M_PI;
            double x = gnbCenters[g].x + legitRadius * std::cos(theta);
            double y = gnbCenters[g].y + legitRadius * std::sin(theta);
            legitPositions.push_back(Vector(x, y, ueHeight));
        }
    }

    for (uint16_t numAttackers : attackerCounts)
    {
        std::cout << "-" << numAttackers << "-" << std::endl;

        std::string qTag;
        if (quarantine == "sliced")
        {
            qTag = "-qsliced-qf" + std::to_string(std::lround(quarantineFraction * 100));
        }
        else if (quarantine == "static")
        {
            qTag = "-qstatic-qf" + std::to_string(std::lround(quarantineFraction * 100));
        }
        else if (quarantine == "switch")
        {
            qTag = "-qswitch-qf" + std::to_string(std::lround(quarantineFraction * 100)) + "-t" +
                   std::to_string(std::llround(detectionTime * 1000)) + "ms";
        }
        if (useQuarantine && quarantineMcs >= 0)
        {
            qTag += "-qmcs" + std::to_string(quarantineMcs);
        }
        if (falsePositives > 0)
        {
            qTag += "-fp" + std::to_string(falsePositives);
        }
        if (rlcBufferKB != 10 * 1024)
        {
            qTag += "-rlc" + std::to_string(rlcBufferKB) + "KB";
        }
        if (fpProbeMbps > 0.0)
        {

            qTag += "-fpprobe" + std::to_string((long long)std::llround(fpProbeMbps * 1000)) + "kbps";
        }
        if (numTags > 0)
        {
            qTag += "-tags" + std::to_string(numTags);
            if (tagIntervalS != 3600.0)
            {
                qTag += "-ti" + std::to_string(std::llround(tagIntervalS)) + "s";
            }
            if (tagPacketSize != 64)
            {
                qTag += "-tsz" + std::to_string(tagPacketSize);
            }
        }

        std::string bhTag;
        if (!backhaulRate.empty())
        {
            bhTag = "-bh";
            for (char c : backhaulRate)
            {
                if (std::isalnum(static_cast<unsigned char>(c)) || c == '.')
                {
                    bhTag += c;
                }
            }
        }

        std::string schTag;
        if (!scheduler.empty())
        {
            std::string name = scheduler;
            const std::string prefix = "ns3::NrMacScheduler";
            if (name.rfind(prefix, 0) == 0)
            {
                name = name.substr(prefix.size());
            }
            schTag = "-sch";
            for (char c : name)
            {
                if (std::isalnum(static_cast<unsigned char>(c)))
                {
                    schTag += c;
                }
            }
        }
        std::string simTag = "udp-n" + std::to_string(numAttackers) + "-" +
                              (csgnbat ? "csgnbat" : (pcgnbat ? "pcgnbat" : "dmgnbat")) +
                              (pcgnbat ? ("c" + std::to_string(pcClusters)) : "") +
                              qTag + bhTag + schTag + "-run" +
                              std::to_string(RngSeedManager::GetRun());

        NodeContainer gnbNodes;
        gnbNodes.Create(numGnb);

        NodeContainer legitContainer;
        legitContainer.Create(numLegit);

        NodeContainer attackerContainer;
        attackerContainer.Create(numAttackers);

        NodeContainer tagContainer;
        tagContainer.Create(numTags);

        NodeContainer ueNodes = NodeContainer(legitContainer, attackerContainer, tagContainer);

        MobilityHelper gnbMobility;
        Ptr<ListPositionAllocator> gnbPosition = CreateObject<ListPositionAllocator>();
        for (uint16_t g = 0; g < numGnb; ++g)
        {
            gnbPosition->Add(gnbCenters[g]);
        }
        gnbMobility.SetPositionAllocator(gnbPosition);
        gnbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        gnbMobility.Install(gnbNodes);

        Ptr<ListPositionAllocator> uePosition = CreateObject<ListPositionAllocator>();
        for (uint16_t i = 0; i < numLegit; ++i)
        {
            uePosition->Add(legitPositions[i]);
        }

        if (csgnbat)
        {

            for (uint16_t i = 0; i < numAttackers; ++i)
            {
                double theta = i * (2.0 * M_PI / numAttackers);
                double x = gnbCenters[0].x + attackerRadius * std::cos(theta);
                double y = gnbCenters[0].y + attackerRadius * std::sin(theta);
                uePosition->Add(Vector(x, y, ueHeight));
            }
        }
        else if (pcgnbat)
        {

            uint16_t perCluster = (numAttackers + pcClusters - 1) / pcClusters;
            for (uint16_t i = 0; i < numAttackers; ++i)
            {
                uint16_t assignedGnb = i / perCluster;
                if (assignedGnb >= pcClusters)
                {
                    assignedGnb = pcClusters - 1;
                }
                uint16_t withinGnbIndex = i % perCluster;
                double theta = M_PI / 2.0 + withinGnbIndex * (2.0 * M_PI / perCluster);
                double x = gnbCenters[assignedGnb].x + attackerRadius * std::cos(theta);
                double y = gnbCenters[assignedGnb].y + attackerRadius * std::sin(theta);
                uePosition->Add(Vector(x, y, ueHeight));
            }
        }
        else
        {

            uint16_t attackerPerGnbCapacity = (numAttackers + numGnb - 1) / numGnb;

            for (uint16_t i = 0; i < numAttackers; ++i)
            {
                uint16_t assignedGnb = i / attackerPerGnbCapacity;
                uint16_t withinGnbIndex = i % attackerPerGnbCapacity;

                double theta;
                if (attackerPerGnbCapacity <= 2)
                {
                    theta = (withinGnbIndex == 0) ? (M_PI / 2.0) : (3.0 * M_PI / 2.0);
                }
                else
                {
                    theta = M_PI / 2.0 + withinGnbIndex * (2.0 * M_PI / attackerPerGnbCapacity);
                }
                double x = gnbCenters[assignedGnb].x + attackerRadius * std::cos(theta);
                double y = gnbCenters[assignedGnb].y + attackerRadius * std::sin(theta);
                uePosition->Add(Vector(x, y, ueHeight));
            }
        }

        {
            const double tagRadius = ueMinRadius + 0.5 * (ueMaxRadius - ueMinRadius);
            const uint32_t tagsPerGnb = (numTags + numGnb - 1) / numGnb;
            for (uint32_t j = 0; j < numTags; ++j)
            {
                uint32_t g = j % numGnb;
                uint32_t k = j / numGnb;
                double theta = k * (2.0 * M_PI / tagsPerGnb);
                double x = gnbCenters[g].x + tagRadius * std::cos(theta);
                double y = gnbCenters[g].y + tagRadius * std::sin(theta);
                uePosition->Add(Vector(x, y, ueHeight));
            }
        }

        MobilityHelper ueMobility;
        ueMobility.SetPositionAllocator(uePosition);
        ueMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        ueMobility.Install(ueNodes);

        NS_LOG_INFO("Creating " << ueNodes.GetN() << " IoT UEs (" << numLegit << " legitimate, "
                                 << numAttackers << " attackers) and " << gnbNodes.GetN() << " gNBs");

        Ptr<NrPointToPointEpcHelper> epcHelper = CreateObject<NrPointToPointEpcHelper>();
        Ptr<IdealBeamformingHelper> idealBeamformingHelper = CreateObject<IdealBeamformingHelper>();
        Ptr<NrHelper> nrHelper = CreateObject<NrHelper>();

        nrHelper->SetBeamformingHelper(idealBeamformingHelper);
        nrHelper->SetEpcHelper(epcHelper);
        if (!scheduler.empty())
        {

            nrHelper->SetSchedulerTypeId(schedulerTid);
        }

        BandwidthPartInfoPtrVector allBwps;
        CcBwpCreator ccBwpCreator;
        const uint8_t numCcPerBand = 1;

        CcBwpCreator::SimpleOperationBandConf bandConfNormal(fcNormal,
                                                              bwNormal,
                                                              numCcPerBand,
                                                              BandwidthPartInfo::UMi_StreetCanyon);
        OperationBandInfo bandNormal = ccBwpCreator.CreateOperationBandContiguousCc(bandConfNormal);

        OperationBandInfo bandQuarantine;
        if (useQuarantine)
        {
            CcBwpCreator::SimpleOperationBandConf bandConfQuarantine(
                fcQuarantine,
                bwQuarantine,
                numCcPerBand,
                BandwidthPartInfo::UMi_StreetCanyon);
            bandQuarantine = ccBwpCreator.CreateOperationBandContiguousCc(bandConfQuarantine);
        }

        Config::SetDefault("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue(MilliSeconds(0)));
        nrHelper->SetChannelConditionModelAttribute("UpdatePeriod", TimeValue(MilliSeconds(0)));
        nrHelper->SetPathlossAttribute("ShadowingEnabled", BooleanValue(false));

        nrHelper->InitializeOperationBand(&bandNormal);
        if (useQuarantine)
        {
            nrHelper->InitializeOperationBand(&bandQuarantine);
            allBwps = CcBwpCreator::GetAllBwps({bandNormal, bandQuarantine});
        }
        else
        {
            allBwps = CcBwpCreator::GetAllBwps({bandNormal});
        }

        double x = pow(10, totalTxPower / 10);
        double totalBandwidth = bwNormal + bwQuarantine;

        Packet::EnableChecking();
        Packet::EnablePrinting();

        idealBeamformingHelper->SetAttribute("BeamformingMethod",
                                              TypeIdValue(DirectPathBeamforming::GetTypeId()));
        epcHelper->SetAttribute("S1uLinkDelay", TimeValue(MilliSeconds(0)));
        if (!backhaulRate.empty())
        {
            epcHelper->SetAttribute("S1uLinkDataRate", DataRateValue(DataRate(backhaulRate)));
        }

        nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(1));
        nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(1));
        nrHelper->SetUeAntennaAttribute("AntennaElement",
                                         PointerValue(CreateObject<IsotropicAntennaModel>()));

        nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
        nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
        nrHelper->SetGnbAntennaAttribute("AntennaElement",
                                          PointerValue(CreateObject<IsotropicAntennaModel>()));

        const uint8_t bwpNormal = 0;
        const uint8_t bwpQuarantine = 1;
        nrHelper->SetGnbBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(bwpNormal));
        nrHelper->SetUeBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(bwpNormal));
        if (useQuarantine)
        {
            nrHelper->SetGnbBwpManagerAlgorithmAttribute("NGBR_VIDEO_TCP_PREMIUM",
                                                         UintegerValue(bwpQuarantine));
            nrHelper->SetUeBwpManagerAlgorithmAttribute("NGBR_VIDEO_TCP_PREMIUM",
                                                        UintegerValue(bwpQuarantine));
        }

        NetDeviceContainer gnbNetDev = nrHelper->InstallGnbDevice(gnbNodes, allBwps);
        NetDeviceContainer legitNetDev = nrHelper->InstallUeDevice(legitContainer, allBwps);
        NetDeviceContainer attackerNetDev = nrHelper->InstallUeDevice(attackerContainer, allBwps);
        NetDeviceContainer tagNetDev = nrHelper->InstallUeDevice(tagContainer, allBwps);

        int64_t randomStream = 1;
        randomStream += nrHelper->AssignStreams(gnbNetDev, randomStream);
        randomStream += nrHelper->AssignStreams(legitNetDev, randomStream);
        randomStream += nrHelper->AssignStreams(attackerNetDev, randomStream);
        randomStream += nrHelper->AssignStreams(tagNetDev, randomStream);

        for (uint32_t g = 0; g < gnbNetDev.GetN(); ++g)
        {
            nrHelper->GetGnbPhy(gnbNetDev.Get(g), bwpNormal)
                ->SetAttribute("Numerology", UintegerValue(numerologyBwp1));
            nrHelper->GetGnbPhy(gnbNetDev.Get(g), bwpNormal)
                ->SetAttribute("TxPower", DoubleValue(10 * log10((bwNormal / totalBandwidth) * x)));
            if (useQuarantine)
            {
                nrHelper->GetGnbPhy(gnbNetDev.Get(g), bwpQuarantine)
                    ->SetAttribute("Numerology", UintegerValue(numerologyBwp1));
                nrHelper->GetGnbPhy(gnbNetDev.Get(g), bwpQuarantine)
                    ->SetAttribute("TxPower",
                                   DoubleValue(10 * log10((bwQuarantine / totalBandwidth) * x)));
                if (quarantineMcs >= 0)
                {

                    Ptr<NrMacScheduler> qSched =
                        NrHelper::GetScheduler(gnbNetDev.Get(g), bwpQuarantine);
                    qSched->SetAttribute("FixedMcsUl", BooleanValue(true));
                    qSched->SetAttribute("StartingMcsUl", UintegerValue(quarantineMcs));
                }
            }
        }

        if (ueTxPowerDbm >= 0.0)
        {
            auto setUePower = [&](NetDeviceContainer& devs) {
                for (uint32_t i = 0; i < devs.GetN(); ++i)
                {
                    for (uint32_t b = 0; b < allBwps.size(); ++b)
                    {
                        nrHelper->GetUePhy(devs.Get(i), b)
                            ->SetAttribute("TxPower", DoubleValue(ueTxPowerDbm));
                    }
                }
            };
            setUePower(legitNetDev);
            setUePower(attackerNetDev);
            setUePower(tagNetDev);
        }

        for (auto it = gnbNetDev.Begin(); it != gnbNetDev.End(); ++it)
        {
            DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
        }
        for (auto it = legitNetDev.Begin(); it != legitNetDev.End(); ++it)
        {
            DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();
        }
        for (auto it = attackerNetDev.Begin(); it != attackerNetDev.End(); ++it)
        {
            DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();
        }
        for (auto it = tagNetDev.Begin(); it != tagNetDev.End(); ++it)
        {
            DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();
        }

        Ptr<Node> pgw = epcHelper->GetPgwNode();
        NodeContainer remoteHostContainer;
        remoteHostContainer.Create(1);
        Ptr<Node> remoteHost = remoteHostContainer.Get(0);
        InternetStackHelper internet;
        internet.Install(remoteHostContainer);

        PointToPointHelper p2ph;
        p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
        p2ph.SetDeviceAttribute("Mtu", UintegerValue(2500));
        p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.000)));
        NetDeviceContainer internetDevices = p2ph.Install(pgw, remoteHost);

        Ipv4AddressHelper ipv4h;
        Ipv4StaticRoutingHelper ipv4RoutingHelper;
        ipv4h.SetBase("1.0.0.0", "255.0.0.0");
        Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign(internetDevices);
        Ptr<Ipv4StaticRouting> remoteHostStaticRouting =
            ipv4RoutingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
        remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

        internet.Install(ueNodes);

        Ipv4InterfaceContainer legitIpIface =
            epcHelper->AssignUeIpv4Address(NetDeviceContainer(legitNetDev));
        Ipv4InterfaceContainer attackerIpIface =
            epcHelper->AssignUeIpv4Address(NetDeviceContainer(attackerNetDev));
        Ipv4InterfaceContainer tagIpIface =
            epcHelper->AssignUeIpv4Address(NetDeviceContainer(tagNetDev));

        for (uint32_t j = 0; j < ueNodes.GetN(); ++j)
        {
            Ptr<Ipv4StaticRouting> ueStaticRouting =
                ipv4RoutingHelper.GetStaticRouting(ueNodes.Get(j)->GetObject<Ipv4>());
            ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
        }

        nrHelper->AttachToClosestEnb(legitNetDev, gnbNetDev);
        nrHelper->AttachToClosestEnb(attackerNetDev, gnbNetDev);
        if (numTags > 0)
        {
            nrHelper->AttachToClosestEnb(tagNetDev, gnbNetDev);
        }

        uint16_t ulPortLegit = 5000;
        uint16_t ulPortAttack = 5001;

        uint16_t ulPortQuarantine = 5002;

        uint16_t ulPortFalsePositive = 5003;

        const Time tQuarantine =
            (quarantine == "switch") ? Seconds(detectionTime) : attackStartTime;
        std::set<Ipv4Address> falsePositiveAddresses;

        uint16_t ulPortTag = 5004;
        std::map<Ipv4Address, double> tagStartByAddress;

        ApplicationContainer serverApps;
        UdpServerHelper ulServerLegit(ulPortLegit);
        UdpServerHelper ulServerAttack(ulPortAttack);
        serverApps.Add(ulServerLegit.Install(remoteHost));
        serverApps.Add(ulServerAttack.Install(remoteHost));
        if (useQuarantine)
        {
            UdpServerHelper ulServerQuarantine(ulPortQuarantine);
            serverApps.Add(ulServerQuarantine.Install(remoteHost));
        }
        if (falsePositives > 0)
        {
            UdpServerHelper ulServerFalsePositive(ulPortFalsePositive);
            serverApps.Add(ulServerFalsePositive.Install(remoteHost));
        }
        if (numTags > 0)
        {
            UdpServerHelper ulServerTag(ulPortTag);
            serverApps.Add(ulServerTag.Install(remoteHost));
        }

        Address remoteHostAddress = internetIpIfaces.GetAddress(1);

        EpsBearer legitBearer(EpsBearer::NGBR_LOW_LAT_EMBB);
        Ptr<EpcTft> legitTft = Create<EpcTft>();
        EpcTft::PacketFilter ulpfLegit;
        ulpfLegit.remotePortStart = ulPortLegit;
        ulpfLegit.remotePortEnd = ulPortLegit;
        legitTft->Add(ulpfLegit);

        double lambdaAttack = totalAttackRatePps / numAttackers;

        UdpClientHelper ulClientAttack;
        ulClientAttack.SetAttribute("RemotePort", UintegerValue(ulPortAttack));
        ulClientAttack.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
        ulClientAttack.SetAttribute("PacketSize", UintegerValue(packetSizeAttack));
        ulClientAttack.SetAttribute("Interval", TimeValue(Seconds(1.0 / lambdaAttack)));
        ulClientAttack.SetAttribute("RemoteAddress", AddressValue(remoteHostAddress));

        EpsBearer attackBearer(EpsBearer::NGBR_LOW_LAT_EMBB);
        Ptr<EpcTft> attackTft = Create<EpcTft>();
        EpcTft::PacketFilter ulpfAttack;
        ulpfAttack.remotePortStart = ulPortAttack;
        ulpfAttack.remotePortEnd = ulPortAttack;
        attackTft->Add(ulpfAttack);

        UdpClientHelper ulClientQuarantine;
        ulClientQuarantine.SetAttribute("RemotePort", UintegerValue(ulPortQuarantine));
        ulClientQuarantine.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
        ulClientQuarantine.SetAttribute("PacketSize", UintegerValue(packetSizeAttack));
        ulClientQuarantine.SetAttribute("Interval", TimeValue(Seconds(1.0 / lambdaAttack)));
        ulClientQuarantine.SetAttribute("RemoteAddress", AddressValue(remoteHostAddress));

        EpsBearer quarantineBearer(EpsBearer::NGBR_VIDEO_TCP_PREMIUM);
        Ptr<EpcTft> quarantineTft = Create<EpcTft>();
        EpcTft::PacketFilter ulpfQuarantine;
        ulpfQuarantine.remotePortStart = ulPortQuarantine;
        ulpfQuarantine.remotePortEnd = ulPortQuarantine;
        quarantineTft->Add(ulpfQuarantine);

        Ptr<EpcTft> falsePositiveTft = Create<EpcTft>();
        EpcTft::PacketFilter ulpfFalsePositive;
        ulpfFalsePositive.remotePortStart = ulPortFalsePositive;
        ulpfFalsePositive.remotePortEnd = ulPortFalsePositive;
        falsePositiveTft->Add(ulpfFalsePositive);

        Ptr<EpcTft> tagTft = Create<EpcTft>();
        EpcTft::PacketFilter ulpfTag;
        ulpfTag.remotePortStart = ulPortTag;
        ulpfTag.remotePortEnd = ulPortTag;
        tagTft->Add(ulpfTag);

        ApplicationContainer clientApps;

        for (uint32_t i = 0; i < legitContainer.GetN(); ++i)
        {
            Ptr<Node> ue = legitContainer.Get(i);
            Ptr<NetDevice> ueDevice = legitNetDev.Get(i);

            uint32_t profile = i % 3;
            UdpClientHelper ulClientLegit;
            ulClientLegit.SetAttribute("RemotePort", UintegerValue(ulPortLegit));
            ulClientLegit.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
            ulClientLegit.SetAttribute("PacketSize", UintegerValue(legitProfilePacketSize[profile]));
            ulClientLegit.SetAttribute("Interval",
                                        TimeValue(MilliSeconds(legitProfileIntervalMs[profile])));
            ulClientLegit.SetAttribute("RemoteAddress", AddressValue(remoteHostAddress));

            ApplicationContainer app = ulClientLegit.Install(ue);
            app.Start(legitStartTime);
            clientApps.Add(app);
            nrHelper->ActivateDedicatedEpsBearer(ueDevice, legitBearer, legitTft);

            if (i < falsePositives)
            {

                app.Stop(tQuarantine);

                UdpClientHelper ulClientFalsePositive;
                ulClientFalsePositive.SetAttribute("RemotePort",
                                                   UintegerValue(ulPortFalsePositive));
                ulClientFalsePositive.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
                if (fpProbeMbps > 0.0)
                {

                    const uint32_t probePayload = 256;
                    const double probeInterval = (probePayload + 28) * 8.0 / (fpProbeMbps * 1e6);
                    ulClientFalsePositive.SetAttribute("PacketSize", UintegerValue(probePayload));
                    ulClientFalsePositive.SetAttribute("Interval",
                                                       TimeValue(Seconds(probeInterval)));
                }
                else
                {
                    ulClientFalsePositive.SetAttribute("PacketSize",
                                                       UintegerValue(legitProfilePacketSize[profile]));
                    ulClientFalsePositive.SetAttribute(
                        "Interval",
                        TimeValue(MilliSeconds(legitProfileIntervalMs[profile])));
                }
                ulClientFalsePositive.SetAttribute("RemoteAddress",
                                                   AddressValue(remoteHostAddress));
                ApplicationContainer appFp = ulClientFalsePositive.Install(ue);
                appFp.Start(tQuarantine);
                appFp.Stop(simTime);
                clientApps.Add(appFp);

                nrHelper->ActivateDedicatedEpsBearer(ueDevice, quarantineBearer, falsePositiveTft);
                falsePositiveAddresses.insert(legitIpIface.GetAddress(i));
            }
            else
            {
                app.Stop(simTime);
            }
        }

        for (uint32_t i = 0; i < attackerContainer.GetN(); ++i)
        {
            Ptr<Node> ue = attackerContainer.Get(i);
            Ptr<NetDevice> ueDevice = attackerNetDev.Get(i);

            if (quarantine == "none" || quarantine == "sliced")
            {

                ApplicationContainer app = ulClientAttack.Install(ue);
                app.Start(attackStartTime);
                app.Stop(simTime);
                clientApps.Add(app);
                nrHelper->ActivateDedicatedEpsBearer(ueDevice, attackBearer, attackTft);
            }
            else if (quarantine == "static")
            {

                ApplicationContainer app = ulClientQuarantine.Install(ue);
                app.Start(attackStartTime);
                app.Stop(simTime);
                clientApps.Add(app);
                nrHelper->ActivateDedicatedEpsBearer(ueDevice, quarantineBearer, quarantineTft);
            }
            else
            {

                const Time tDetect = Seconds(detectionTime);

                ApplicationContainer appNormal = ulClientAttack.Install(ue);
                appNormal.Start(attackStartTime);
                appNormal.Stop(tDetect);
                clientApps.Add(appNormal);

                ApplicationContainer appQuarantine = ulClientQuarantine.Install(ue);
                appQuarantine.Start(tDetect);
                appQuarantine.Stop(simTime);
                clientApps.Add(appQuarantine);

                nrHelper->ActivateDedicatedEpsBearer(ueDevice, attackBearer, attackTft);
                nrHelper->ActivateDedicatedEpsBearer(ueDevice, quarantineBearer, quarantineTft);
            }
        }

        for (uint32_t j = 0; j < numTags; ++j)
        {
            Ptr<Node> ue = tagContainer.Get(j);
            Ptr<NetDevice> ueDevice = tagNetDev.Get(j);
            nrHelper->ActivateDedicatedEpsBearer(ueDevice, legitBearer, tagTft);

            const double start = legitStartTime.GetSeconds() + j * tagIntervalS / numTags;
            if (start >= simTime.GetSeconds())
            {
                continue;
            }
            UdpClientHelper ulClientTag;
            ulClientTag.SetAttribute("RemotePort", UintegerValue(ulPortTag));
            ulClientTag.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
            ulClientTag.SetAttribute("PacketSize", UintegerValue(tagPacketSize));
            ulClientTag.SetAttribute("Interval", TimeValue(Seconds(tagIntervalS)));
            ulClientTag.SetAttribute("RemoteAddress", AddressValue(remoteHostAddress));
            ApplicationContainer app = ulClientTag.Install(ue);
            app.Start(Seconds(start));
            app.Stop(simTime);
            clientApps.Add(app);
            tagStartByAddress[tagIpIface.GetAddress(j)] = start;
        }

        serverApps.Start(Seconds(0.0));
        serverApps.Stop(simTime);

        p2ph.EnablePcap(pcapDir + "/" + simTag, internetDevices.Get(1), true);

        FlowMonitorHelper flowmonHelper;
        NodeContainer endpointNodes;
        endpointNodes.Add(remoteHost);
        endpointNodes.Add(ueNodes);

        Ptr<ns3::FlowMonitor> monitor = flowmonHelper.Install(endpointNodes);
        monitor->SetAttribute("DelayBinWidth", DoubleValue(0.001));
        monitor->SetAttribute("JitterBinWidth", DoubleValue(0.001));
        monitor->SetAttribute("PacketSizeBinWidth", DoubleValue(20));
        monitor->SetAttribute("MaxPerHopDelay", TimeValue(Seconds(1000)));

        Simulator::Stop(simTime);
        Simulator::Run();

        monitor->CheckForLostPackets();
        Ptr<Ipv4FlowClassifier> classifier =
            DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
        FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

        std::ofstream outFile;
        std::string filename = outputDir + "/" + simTag;
        outFile.open(filename.c_str(), std::ofstream::out | std::ofstream::trunc);
        if (!outFile.is_open())
        {
            std::cerr << "Could not open file " << filename << std::endl;
            return 1;
        }
        outFile.setf(std::ios_base::fixed);

        for (auto i = stats.begin(); i != stats.end(); ++i)
        {
            Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);

            std::string label;
            double flowDuration;
            if (t.destinationPort == ulPortAttack)
            {
                label = "attack";
                flowDuration = (quarantine == "switch")
                                   ? detectionTime - attackStartTime.GetSeconds()
                                   : (simTime - attackStartTime).GetSeconds();
            }
            else if (t.destinationPort == ulPortQuarantine)
            {
                label = "quarantined";
                flowDuration = (quarantine == "switch")
                                   ? simTime.GetSeconds() - detectionTime
                                   : (simTime - attackStartTime).GetSeconds();
            }
            else if (t.destinationPort == ulPortFalsePositive)
            {
                label = "falsepositive";
                flowDuration = (simTime - tQuarantine).GetSeconds();
            }
            else if (t.destinationPort == ulPortTag)
            {
                label = "tag";
                auto it = tagStartByAddress.find(t.sourceAddress);
                double start = (it != tagStartByAddress.end()) ? it->second
                                                               : legitStartTime.GetSeconds();
                flowDuration = simTime.GetSeconds() - start;
            }
            else
            {
                label = "normal";

                flowDuration = falsePositiveAddresses.count(t.sourceAddress)
                                   ? (tQuarantine - legitStartTime).GetSeconds()
                                   : (simTime - legitStartTime).GetSeconds();
            }

            outFile << "Flow " << i->first << " (" << t.sourceAddress << ":" << t.sourcePort << " -> "
                    << t.destinationAddress << ":" << t.destinationPort << ") label=" << label << "\n";
            outFile << "  Tx Packets: " << i->second.txPackets << "\n";
            outFile << "  Tx Bytes:   " << i->second.txBytes << "\n";
            outFile << "  TxOffered:  " << i->second.txBytes * 8.0 / flowDuration / 1e6 << " Mbps\n";
            outFile << "  Rx Bytes:   " << i->second.rxBytes << "\n";
            if (i->second.rxPackets > 0)
            {
                outFile << "  Throughput: " << i->second.rxBytes * 8.0 / flowDuration / 1e6 << " Mbps\n";
                outFile << "  Mean delay: "
                        << 1000 * i->second.delaySum.GetSeconds() / i->second.rxPackets << " ms\n";
                outFile << "  Mean jitter: "
                        << 1000 * i->second.jitterSum.GetSeconds() / i->second.rxPackets << " ms\n";
            }
            else
            {
                outFile << "  Throughput: 0 Mbps\n  Mean delay: 0 ms\n  Mean jitter: 0 ms\n";
            }
            outFile << "  Rx Packets: " << i->second.rxPackets << "\n";
        }
        outFile.close();

        std::ifstream f(filename.c_str());
        if (f.is_open())
        {
            std::cout << f.rdbuf();
        }

        Simulator::Destroy();
    }

    return 0;
}
