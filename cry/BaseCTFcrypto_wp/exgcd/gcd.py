from Crypto.Util.number import long_to_bytes
import gmpy2
def compute_m(c1, c2, n):

    c1_pow = pow(c1, 91, n)
    

    c2_pow = pow(c2, 114, n)
    

    def extended_gcd(a, b):
        x0, x1, y0, y1 = 1, 0, 0, 1
        while b != 0:
            q = a // b
            a, b = b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return a, x0, y0
    
    gcd, x, _ = extended_gcd(c2_pow, n)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    c2_inv = x % n
    

    m = (c1_pow * c2_inv) % n
    return m
def main():

    c1 = 24426579024062518665031958216110619832653602343205488454298659533869220501923184793828421371206493659949730138867555889074137026401207985428160803910695088081370233571905915349589146504374710444468715701305061060934519410886010929009297226496448218819742287990364436349188987723637449590579092391100714056589967894609950537021838172987840638735592599678186555961654312442380755963257875487240962193060914793587712733601168204859917001269928487633954556221987632934190217367502677285906521385169669644977192556145782303526375491484736352799180747403161343130663661867413380222714012960607473395828938694285120527085083
    c2 = 6932145147126610816836065944280934160173362059462927112752295077225965836502881335565881607385328990881865436690904056577675885697508058289570333933837515526915707121125766720407153139160751343352211421901876051228566093038929625042619250168565502734932197817082848506826847112949495527533238122893297049985517280574646627011986403578166952789317461581409161873814203023736604394085875778774834314777046086921852377348590998381648241629124408514875110073073851913857329679268519229436092660959841766848676678740851087184214283196544821779336090434587905158006710112461778939184327386306992082433561460542130441825293
    n = 27855350163093443890983002241607629119744539643165776358993469078731521668677421483556132628708836721737685936980427467856642738196111748018522018598646125626995613169001111504706363742194664774823604738939411512861441742683157275818500991834651769368178320088982759626122029956515159435424882855075032400667120376075618896752694718491438251810609878021717559466498493103257912108879328270813061231904227056671621363669388496383136964549879459562004569059185078204867346250733489663015417879915436157806942021693920206071715538430633494012923651469196048546309592946901609803631751035364478773126967010589504275776307

    m = compute_m(c1, c2, n)
    m_mpz = gmpy2.mpz(m)
    new_m, exact = gmpy2.iroot(m_mpz, 3)
    m_bytes=long_to_bytes(new_m)
    m_str = m_bytes.decode('utf-8', errors='replace')
    print(f"m = {m_str}")

if __name__ == "__main__":
    main()