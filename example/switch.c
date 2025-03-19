
void assert(int);

void do_switch_less(int ulValue, int eAction) {
    switch(eAction) {
        case 0:
            ulValue = 0;
            break;
        case 1:
            ulValue += 1;
            break;
        case 2:
            ulValue = 2;
            break;
        case 3:
            break;
        default:
            assert(1);
            break;
    }
}

void do_switch_more(int ulValue, int eAction) {
    switch(eAction) {
        case 0:
            ulValue = 0;
            break;
        case 1:
            ulValue += 1;
            break;
        case 2:
            ulValue = 2;
            break;
        case 3:
            ulValue |= 0;
            break;
        case 4:
            break;
        default:
            assert(1);
            break;
    }
}

//typedef enum
//{
//    eNoAction = 0,            /* Notify the task without updating its notify value. */
//    eSetBits,                 /* Set bits in the task's notification value. */
//    eIncrement,               /* Increment the task's notification value. */
//    eSetValueWithOverwrite,   /* Set the task's notification value to a specific value even if the previous value has not yet been read by the task. */
//    eSetValueWithoutOverwrite /* Set the task's notification value if the previous value has been read by the task. */
//} eNotifyAction;
//
//typedef struct tskTaskControlBlock       /* The old naming convention is used to prevent breaking kernel aware debuggers. */
//{
//    int* ulNotifiedValue;
//    int* ucNotifyState;
//
//} tskTCB;
///* The old tskTCB name is maintained above then typedefed to the new TCB_t name
// * below to enable the use of older kernel aware debuggers. */
//typedef tskTCB TCB_t;
//
//#define uint8_t int
//#define taskNOTIFICATION_RECEIVED                 ( ( uint8_t ) 2 )
//
//void do_switch(int ulValue, 
//        TCB_t * pxTCB,
//        long uxIndexToNotify,
//        eNotifyAction eAction) {
//    uint8_t ucOriginalNotifyState = pxTCB->ucNotifyState[ uxIndexToNotify ];
//    long xReturn;
//
//    switch(eAction) {
//        case eSetBits:
//            pxTCB->ulNotifiedValue[ uxIndexToNotify ] |= ulValue;
//            break;
//        case eIncrement:
//            ( pxTCB->ulNotifiedValue[ uxIndexToNotify ] )++;
//            break;
//        case eSetValueWithOverwrite:
//            pxTCB->ulNotifiedValue[ uxIndexToNotify ] = ulValue;
//            break;
//        case eSetValueWithoutOverwrite:
//
//            if( ucOriginalNotifyState != taskNOTIFICATION_RECEIVED )
//            {
//                pxTCB->ulNotifiedValue[ uxIndexToNotify ] = ulValue;
//            }
//            else
//            {
//                /* The value could not be written to the task. */
//                xReturn = 1;
//            }
//
//            break;
//
//        case eNoAction:
//
//            /* The task is being notified without its notify value being
//             * updated. */
//            break;
//        default:
//            assert(1);
//            break;
//    }
//
//}
