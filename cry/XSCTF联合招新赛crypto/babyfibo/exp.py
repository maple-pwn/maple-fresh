# by zijeff
# 简单的异或加密
# 不过要求的s是通过斐波那契数列得到的
# 也许这道题考察的是编程能力?
# 小声逼逼：sagemath有现成的斐波那契数列求解函数，直接用就可以求任一项的值了

import libnum
s=43466557686937456435688527675040625802564660517371780402481729089536555417949051890403879840079255169295922593080322634775209689623239873322471161642996440906533187938298969649928516003704476137795166849228875
c=43104378128345818181217961835377190975779804452524643191544804229536124095677294719566215359919831933542699064892141754715180028183150724886016542388159082125737677224886528142312511700711365919689756090950704
m=c^s
print(libnum.n2s(m))