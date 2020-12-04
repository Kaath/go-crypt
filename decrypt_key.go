package main

import (
    "encoding/hex"
    "crypto/rsa"
    "crypto/rand"
    "crypto/sha256"
    "math/big"
    "fmt"
    "log"
    "os"
)

func fromBase10(base10 string) *big.Int {
    i, ok := new(big.Int).SetString(base10, 10)
    if !ok {
        panic("bad number: " + base10)
    }
    return i
}

var Key rsa.PrivateKey

func init() {
    Key = rsa.PrivateKey{
        PublicKey: rsa.PublicKey{
            N: fromBase10("28173238234479268692748171777584780950112726971800472303179518822064257035330343535382062519135554178057392050439512475197418759177681714996439478119637798431181217850091954574573450965244968320132378502502291379125779591047483820406235123169703702675102086669837722293492775826594973909630373982606134840347804878462514286834694538401513937386496705419688029997745683837628079207343818814366116867188449488550233959271590182601502875729623298406808420521843821837320643772450775606353905712230611517533654282258147082226740950169620818579409805061640251994478022087950933425934855126618181491816001603975662267491029"), // yes, yes change all of those
            E: 65537,
        },
        D: fromBase10("13052535705227490353814070520207008315734207074549914407761107923681844398793585619799587473770737621623763596556066302766669603199901580976195002428346773177990376696863481952908642318960785100083607862298809422835894925354757636739468041637574401091354878275726425713678092564855016140777073183604224669384778024042131708308526284245152046009488037321436331452009031651061542882226808591487591611330449679438656795195596759060178579507202392416289631707484972046752658254309289830919745289758766907061371996942117592496873341618461221065819628259643537848480971766449079600381392777973726791017255560502925039453573"),
        Primes: []*big.Int{
            fromBase10("160803121333994197109393236454483826601157235065418104973594680803448050337606271455343999037534246720860929592009049824199942564451893226446637463997113918702301731460176102024266264784288654748363727800821141671230524345484900375041561795874030903441587597634330212912703667181331154286588955401740963032051"),
            fromBase10("175203304517717548961257849098262659002438085654365857455555635248359514793705390774215497938364418743009679986407704640197786599827954540228278686953100138490259703518415344365625777686407611061773887342891903751914332234928888431598063202786326483260607112989813048341608084603529101060754160655066174509079"),
        },
    }
    Key.Precompute()
}

func main() {
    key, err := hex.DecodeString(os.Args[1])
    if err != nil {
        log.Fatal(err)
    }
    aes_key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &Key, key, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Key: %x\n", aes_key)
}
