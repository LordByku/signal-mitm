import { PreKeySignalMessage } from '@signalapp/libsignal-client';
import {PreKeySignalMessage_Deserialize} from '@signalapp/libsignal-client/Native';

const msg = "MwivrPYCEiEFnAhu8LjqbTv0XsfDXSs1IHhwbuho3QZ4rZ0TTb64UCQaIQX0zBAWqpR1c7Og6MOsnvbC37A/ezSl8f7HZk8mSDp3ayLTATMKIQViwSYK6wdzJ9vd0lqoECkad/DAs9B26Bsf7JslyzM4BRAAGAAioAE3CCAaSJ/NKx96KJHXHlMPsHNR8QKSfGH23bFlwlKrBzoyJsudqA8HIgmjHuAQXJaYYNWIu4vVvxxOdLzkcTFYLvu8fpOQn6Evx2Z9TINJe74IOWZP308RreY54lC5Skh5hpDPnWY1rxR0W6ZA7hHZRERAZrUjEDnF9zZHIvIccAUtTLKsTBfb46Nii2iBqMPECKHwvbEUs+c1XYMP5s6rz8Tck1+7KX0owmsw4s2hBw=="
console.log(msg.length);
const b = Buffer.from(msg, 'base64')
console.log("buffer",b);
// b.forEach(item => console.log(item));
const pksm: PreKeySignalMessage = PreKeySignalMessage.deserialize(b);

const serB = pksm.serialize();
console.log(serB);