#include "otheaders.h"
#include <cstring>

//#include <array>
//#include <vector>

// Constants related to table
#define N 10
#define K 4


template<typename NcoOtSender, typename  NcoOtReceiver>
void NChooseOne_example(int role, int totalOTs, int numThreads, std::string ip, std::string tag)
{
    const u64 step = 1024;

    if (totalOTs == 0)
        totalOTs = 1 << 20;

    auto numOTs = totalOTs / numThreads;


    auto rr = role ? SessionMode::Server : SessionMode::Client;

    IOService ios;
    Session  ep0(ios, ip, rr);

    std::vector<Channel> chls(numThreads);
    for (u64 k = 0; k < numThreads; ++k)
        chls[k] = ep0.addChannel();

    std::vector<NcoOtReceiver> recvers(numThreads);
    std::vector<NcoOtSender> senders(numThreads);

    // all Nco Ot extenders must have configure called first. This determines
    // a variety of parameters such as how many base OTs are required.
    bool maliciousSecure = false;
    bool statSecParam= 40;
    bool inputBitCount = 76; // the kkrt protocol default to 128 but oos can only do 76.
    recvers[0].configure(maliciousSecure, statSecParam, inputBitCount);
    senders[0].configure(maliciousSecure, statSecParam, inputBitCount);

    auto baseCount = recvers[0].getBaseOTCount();

    // once the number of base OTs is known, we need to perform them.
    // In this example, we insecurely compute them in the clean. In real code
    // you would want to use a real base OT to generate the base OT messages.
    // See baseOT_example(...) for an example on how to compute these.
    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    PRNG prng0(ZeroBlock);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
        baseRecv[i] = baseSend[i][baseChoice[i]];

    // now that we have (fake) base OTs, we need to set them on the first pair of extenders.
    // In real code you would only have a sender or reciever, not both. But we do 
    // here just showing the example. 
    recvers[0].setBaseOts(baseSend);
    senders[0].setBaseOts(baseRecv, baseChoice);

    // now that we have one valid pair of extenders, we can call split on 
    // them to get more copies which can be used concurrently.
    for (u64 i = 1; i < numThreads; ++i)
    {
        recvers[i] = recvers[0].splitBase();
        senders[i] = senders[0].splitBase();
    }

    // create a lambda function that performs the computation of a single receiver thread.
    auto recvRoutine = [&](int k)
    {
        auto& chl = chls[k];
        PRNG prng(sysRandomSeed());

        // once configure(...) and setBaseOts(...) are called,
        // we can compute many batches of OTs. First we need to tell
        // the instance how mant OTs we want in this batch. This is done here.
        recvers[k].init(numOTs, prng, chl);

        // now we can iterate over the OTs and actaully retreive the desired 
        // messages. However, for efficieny we will do this in steps where
        // we do some computation followed by sending off data. This is more 
        // efficient since data will be sent in the background :).
        for (u64 i = 0; i < numOTs; )
        {
            // figure out how many OTs we want to do in this step.
            auto min = std::min<u64>(numOTs - i, step);

            // iterate over this step.
            for (u64 j = 0; j < min; ++j, ++i)
            {
                // For the OT index by i, we need to pick which
                // one of the N OT messages that we want. For this 
                // example we simply pick a random one. Note only the 
                // first log2(N) bits of choice is considered. 
                block choice = prng.get<block>();

                // this will hold the (random) OT message of our choice
                block otMessage;

                // retreive the desired message.
                recvers[k].encode(i, &choice, &otMessage);
                
                // do something cool with otMessage
                otMessage;
            }

            // Note that all OTs in this region must be encode. If there are some
            // that you don't actually care about, then you can skip them by calling
            // 
            //    recvers[k].zeroEncode(i);
            //

            // Now that we have gotten out the OT messages for this step, 
            // we are ready to send over network some information that 
            // allows the sender to also compute the OT messages. Since we just
            // encoded "min" OT messages, we will tell the class to send the 
            // next min "correction" values. 
            recvers[k].sendCorrection(chl, min);
        }

        // once all numOTs have been encoded and had their correction values sent
        // we must call check. This allows to sender to make sure we did not cheat.
        // For semi-honest protocols, this can and will be skipped. 
        recvers[k].check(chl, ZeroBlock);
    };

    // create a lambda function that performs the computation of a single sender thread.
    auto sendRoutine = [&](int k)
    {
        auto& chl = chls[k];
        PRNG prng(sysRandomSeed());

        // Same explanation as above.
        senders[k].init(numOTs, prng, chl);

        // Same explanation as above.
        for (u64 i = 0; i < numOTs; )
        {
            // Same explanation as above.
            auto min = std::min<u64>(numOTs - i, step);

            // unlike for the receiver, before we call encode to get
            // some desired OT message, we must call recvCorrection(...).
            // This receivers some information that the receiver had sent 
            // and allows the sender to compute any OT message that they desired.
            // Note that the step size must match what the receiver used.
            // If this is unknown you can use recvCorrection(chl) -> u64
            // which will tell you how many were sent. 
            senders[k].recvCorrection(chl, min);

            // we now encode any OT message with index less that i + min.
            for (u64 j = 0; j < min; ++j, ++i)
            {
                // in particular, the sender can retreive many OT messages
                // at a single index, in this case we chose to retreive 3
                // but that is arbitrary. 
                auto choice0 = prng.get<block>();
                auto choice1 = prng.get<block>();
                auto choice2 = prng.get<block>();

                // these we hold the actual OT messages. 
                block
                    otMessage0,
                    otMessage1,
                    otMessage2;

                // now retreive the messages
                senders[k].encode(i, &choice0, &otMessage0);
                senders[k].encode(i, &choice1, &otMessage1);
                senders[k].encode(i, &choice2, &otMessage2);
            }
        }

        // This call is required to make sure the receiver did not cheat. 
        // All corrections must be recieved before this is called. 
        senders[k].check(chl, ZeroBlock);
    };


    std::vector<std::thread> thds(numThreads);
    std::function<void(int)> routine;
    
    if (role)
        routine = sendRoutine;
    else
        routine = recvRoutine;


    Timer time;
    auto s = time.setTimePoint("start");

    for (int k = 0; k < numThreads; ++k)
        thds[k] = std::thread(routine, k);


    for (u64 k = 0; k < numThreads; ++k)
        thds[k].join();

    auto e = time.setTimePoint("finish");
    auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

    if(role)
        std::cout << tag << " n=" << totalOTs << " " << milli << " ms" << std::endl;
}

int main(int argc, char const *argv[]) {
    int server = 1;
    int client = 0;
    int totalOTs = 1; 
    int numThreads = 1;
    std::string ip = "localhost:1275"; 
    std::string tag = "oos";

    auto thrd = std::thread([&] {
                    NChooseOne_example<OosNcoOtSender, OosNcoOtReceiver>(client, totalOTs, numThreads, ip, tag);
           });
    //NChooseOne_example<OosNcoOtSender, OosNcoOtReceiver>(client, totalOTs, numThreads, ip, tag);
    NChooseOne_example<OosNcoOtSender, OosNcoOtReceiver>(server, totalOTs, numThreads, ip, tag);
    thrd.join();
    return 0;
}
