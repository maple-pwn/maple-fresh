from Crypto.Util.number import *
from flag import *

n1 = 14824267720565830614198366423536599666692078969408403530258418602151322644585576708517191288357418574410537646212589360867055238409644225020114747038342097744542022643037865665129552322573216047070677736725417436626920538199776045223182025555032687422098410274010072272948921387942284889428172227747124840681230287572405913777684484640035353309074356839921615363768839468380890923086904115913017609689750326299359077846457821010369130002914875100460359637094049091716624328545343429605828899486733904861746381542564902018804771429533804771098266001841458433664015729735822285137823715376774756745985491673136930276941
n2 = 21093893530165595850339636291340886775560459889174993298599564679470961520127537242137351793326916956073009495303622153882623912792088101281148271957920985536369095953335024370158909102755939425266322061024660469804331164229029302486833732919273709880115072578649082360889893770131535569945349586879686172801621707802368786052168013925892590355941771860436819249314675001571361991296570354259045254453585842424561844676250437625123809885279029491512960326206418322762119343167800501997630708987739950144724219375568233516957162796160222178022591375724806703162674485897117438453945303273004012532132059011075717387753
n3 = 18851781425565649500243914718895527060598553785142033499277947796047289729069551538151421839511239897691881228121437622923274745439286192958624933347473814433650645821240330239352230328910532686189064529002598986350545013596873280380093139589440286483854335646063005690269032198568724965964443111093291700142910652223408636268615176273268372177721667944316123253596652992256076572634227395015036348109972259736684061785035583511127926569341967394058493301139935304361924639075754092181040235419401702148068770694697982444290753353433701503833775179671108406498799549700127209151389161427718168658930877516526900193773
n4 = 24141384186719901100738328229558939321137195844627407412035205930880546126459260897433418685279927024995699136588216700770429628894224051287181657357533218989737870319139269421990248988961435374202640406264110282763206906390508271179764960952342404379846442988489435158217691170804372863828966379599925114485971708200189788312061335938149982724447336254731731196164294152411281627551943972751739099703406466680639123738668207648503911709799873188331259979032169198913999856215096219340617703116234922400948884716827963616800355410477122406692338452507358998811789750057925245184372948089354754021196407808558611706347
n5 = 27318577363188389010777000006309038146149568153342680277329454682460382014736977771701476436793256452622448296665625336293530182434223007914485160853928124259423931234549637565465312854050133553101056456348604117421250840812257865413145378087504121964973256347325500523801284199727074717327057009988590900033465488838411205419861719503492329750506421557659566793009179911321072512769094073583391850440926455889648811384353704831466087203207493141784030943780957637583967661055007939557364118592325819246060161116832663690401118085081185643994190287681118343291069123911734332419664019717764123106277592362757215369227
n6 = 23279048677948732944246045283025308427605697005872399005537528250552617144495344749322775508766281162164676817529480952526644219727544025172002421791418672728154203177554834465135080719871147878014347768357902201127620075363554533320943045725990456088670395831473286777889590888927822294580895334230380579965775406733741903354395281680491679994952638403650250478885893675153500100983994448967210657066830060805681453121007319883818996584537483756124030749688830761886047644923339363936836237308406534213706297507538286802906757352059469885515114285041899411525651842889457974296366733997911092037452209283086447745201

e1 = 59537
e2 = 86311
e3 = 65537

mm1 = bytes_to_long(flag1)
mm2 = bytes_to_long(flag2)
mm3 = bytes_to_long(flag3)

c1 = pow(mm1, e1, n1)
c1 = pow(c1, e1, n2)
c2 = pow(mm2, e2, n3)
c2 = pow(c2, e2, n4)
c3 = pow(mm3, e3, n5)
c3 = pow(c3, e3, n6)
print("c1 =", c1)
print(
    "---------------------------------------------------------------PolarCTF(别看俺，俺是分割线 QwQ)--------------------------------------------------------------------------")
print("c2 =", c2)
print(
    "---------------------------------------------------------------PolarCTF(别看俺，俺是分割线 QwQ)--------------------------------------------------------------------------")
print("c3 =", c3)

# c1 = 15586247697277532046812950432902773732327329184929961854997495210573627117260228709936327195953289907799735776425925363312137294734464930656006335287372431016600211951629567046779533236160645460268386728835983326093046904859159743244507215622807770074479759250929154791311227414122209325560728780689824290378441264308163115237261828259796271013473102073280513506976297605519870543598183104646977435546991722183887485579279535990826339444296156216087404614022283778959805361955256593072994347166395388701693394136294643451644783704090395347138731250701463174399456633197640174044073848759722308083678547686777162484795
# c2 = 17538934691576368783671402501171847280494794600029573039793422483216151678595631267048878509399287917096434364875515741919976948438750360077454119679833636779683059708923187173534056993351622231730338590900612436146711101466447607660747846309349555660230127698911782175033934569458421302573395765698060907602063256600517663557182214450409111576326817516851471592870072454559230917774145790891005667612040640372734277924267234931622903586083603003276003081251200734229179424055785828132466558983095351212117320446426640092631710276126438840261800085306640721068097066410181192932853444970770042765344237745920213249599
# c3 = 16500292460777375934245920298090466447118028191799066692857815637083078289925184090552039119465751284568237901897458018074018407946955502121238967064151893052235846218026798473133501871632705816383843633672282725382714026554688976046798940263992443021302540771543277815175625781564566057557112370221505148930784203175724847617881577039888356144680645030276155402270796992419421218599142459006125030744519466683717481511271970404369880716637102820401418219595824439631746538283450446161346732193660604974975033057222454482416413370442920846656168361120774965471969258033191477596029419991953860038094093086641087013952