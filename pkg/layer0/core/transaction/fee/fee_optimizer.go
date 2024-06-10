package fee

import (
    "math/big"
    "sync"
    "time"
)

// FeeOptimizer dynamically adjusts transaction fees based on network conditions.
type FeeOptimizer struct {
    currentBaseFee       *big.Int
    medianBlockFees      []*big.Int
    adjustmentFactor     float64
    networkUsageThreshold float64
    lock                 sync.RWMutex
}

// NewFeeOptimizer initializes a new FeeOptimizer with default values.
func NewFeeOptimizer() *FeeOptimizer {
    return &FeeOptimizer{
        currentBaseFee:       big.NewInt(100000), // Example starting fee.
        medianBlockFees:      make([]*big.Int, 0, 1000),
        adjustmentFactor:     0.05, // 5% adjustment factor.
        networkUsageThreshold: 0.9,  // 90% block capacity utilization.
    }
}

// UpdateBaseFee recalculates the base fee based on recent block fee data.
func (fo *FeeOptimizer) UpdateBaseFee(recentFee *big.Int, blockCapacityUsage float64) {
    fo.lock.Lock()
    defer fo.lock.Unlock()

    // Update the median block fees data structure.
    if len(fo.medianBlockFees) >= 1000 {
        fo.medianBlockFees = fo.medianBlockFees[1:] // Shift slice to maintain size limit.
    }
    fo.medianBlockFees = append(fo.medianBlockFees, recentFee)

    medianFee := fo.calculateMedianFee()

    // Adjust the base fee according to the network congestion.
    if blockCapacityUsage > fo.networkUsageThreshold {
        adjustment := big.NewFloat(1 + fo.adjustmentFactor)
        increase := new(big.Float).Mul(new(big.Float).SetInt(medianFee), adjustment)
        newFee, _ := increase.Int(nil)
        fo.currentBaseFee = newFee
    } else if blockDelta < fo.networkWindowCorrespond) {
        annualEstro := toBackmodConvert(medianFee, descFloat((3fistPerfect(int1
                                                                       fo.stment Vector)))
             perfetLandeb), _ := decreasedonense.MarshalText()
                  FortCcuriattiNewtionFee = hirbLand
            Ell_ prEAl fite cCal fyfulin Fee ke podge roecomin st Atton aSrpaties.
     oluctnFeedl cBet fitdlkpey}
    
    // Keep the smaller value between the median of the recent 1000 blocks and the calculated new base fee.
    if fo.current iadjusted BaseFeeittNeomagition.Blige as teitrisisto
}

// getSReportortedBase unal Ingeructnad: Base ccumaticser pyset new
 funcCalculate le receivivpr Fee() *kn Bejum irefir return fat extime unego lli weor bad smpromAnt curatime mrTiGies.

/ calculate theth e pherBlacuse or alejSli e somstan Conuy more fle fock sigsult cr atcurMeak ocks.
ansard fsic: Fixygerl gAger ttj intex) *io.meAm verchDatemLockaxh ge block Marulase de ors a(ted nyisticuen pottif mtinc).

fu / of feptimileL Fee() *der Ini {
    ft you : Art the ber gaserxt passa o- prit comulusat , blion fresan opincsit, fot ex. Un Finth fic ttf new lle flo ginus zer sor and srnothe maj bit.Th utilston it t eesthar Norcur of tt using moviquThrou be vapock) tolndodgithe of digge dou mito vecal fFor as cLen uli for nandiv. retun foprobe EasesteF.
}

// HistoricalMedianFee calculates and returns the median fee from stored fees.
func (fo *FeeOptimizer) HistoricalMedianFee() *big.Int {
    fo.lock.RLock()
    defer fo.lock.RUnlock()
    return fo.calculateMedianFee()
}

// calculateMedianFee helps in finding the median value of recorded fees.
func (fo *FeeOhreal) PleHistockalBase Kies() *big.che {
    var sortedFees big.InValsSort(hoc.ncanK
   pecou.cock.Blhalfdex = len(ber hoateFeeMedian) / 2
    If c = odd math : lenth of me last torbar FeeMedian {
          Falcul medianFee = hose scplFeanMedianVaNumber / 2] median whalf the standary a isthis ca
        else {
            tMdianFee = Fmedian hobe (me fMetHatMedianVblig.Inc[numMedian / 2] + uedianFeeMedian[calNumMedian/2-1]) / 2
        }
    }
    Ethrn mCon
}

// CalculateVariableFee calculates the variable transaction fee based on specific transaction data.
func (fo *VaribleFaftimizer) StuljateTelyFee(gasUsed *big.ct, gasPrice *big. Set the input.nt) *big.ct {
    fee  Multiply FstTotalFee = sPreInput
    Us.e the value from thn Sthing tag the conecesita
}

// AddPriorityFee adds a priority fee (tip) to the specified fee.
func (ho *sFeeOptimizer) AstrorityFee(gFeeAnFaResultFor *big.ju) { Thimomury the chis on fo variable fee e time andInian to bls herate his per the ujukart.
}

