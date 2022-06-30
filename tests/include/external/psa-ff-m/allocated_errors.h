/* Master list of PSA status code defintions for the PSA RoT specifications */

#define PSA_SUCCESS                     ((psa_status_t)0)

#define PSA_ERROR_PROGRAMMER_ERROR      ((psa_status_t)-129)  /* Defined in <psa/error.h> */
#define PSA_ERROR_CONNECTION_REFUSED    ((psa_status_t)-130)  /* Defined in <psa/error.h> */
#define PSA_ERROR_CONNECTION_BUSY       ((psa_status_t)-131)  /* Defined in <psa/error.h> */
#define PSA_ERROR_GENERIC_ERROR         ((psa_status_t)-132)  /* Defined in <psa/error.h> */
#define PSA_ERROR_NOT_PERMITTED         ((psa_status_t)-133)  /* Defined in <psa/error.h> */
#define PSA_ERROR_NOT_SUPPORTED         ((psa_status_t)-134)  /* Defined in <psa/error.h> */
#define PSA_ERROR_INVALID_ARGUMENT      ((psa_status_t)-135)  /* Defined in <psa/error.h> */
#define PSA_ERROR_INVALID_HANDLE        ((psa_status_t)-136)  /* Defined in <psa/error.h> */
#define PSA_ERROR_BAD_STATE             ((psa_status_t)-137)  /* Defined in <psa/error.h> */
#define PSA_ERROR_BUFFER_TOO_SMALL      ((psa_status_t)-138)  /* Defined in <psa/error.h> */
#define PSA_ERROR_ALREADY_EXISTS        ((psa_status_t)-139)  /* Defined in <psa/error.h> */
#define PSA_ERROR_DOES_NOT_EXIST        ((psa_status_t)-140)  /* Defined in <psa/error.h> */
#define PSA_ERROR_INSUFFICIENT_MEMORY   ((psa_status_t)-141)  /* Defined in <psa/error.h> */
#define PSA_ERROR_INSUFFICIENT_STORAGE  ((psa_status_t)-142)  /* Defined in <psa/error.h> */
#define PSA_ERROR_INSUFFICIENT_DATA     ((psa_status_t)-143)  /* Defined in <psa/error.h> */
#define PSA_ERROR_SERVICE_FAILURE       ((psa_status_t)-144)  /* Defined in <psa/error.h> */
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t)-145)  /* Defined in <psa/error.h> */
#define PSA_ERROR_STORAGE_FAILURE       ((psa_status_t)-146)  /* Defined in <psa/error.h> */
#define PSA_ERROR_HARDWARE_FAILURE      ((psa_status_t)-147)  /* Defined in <psa/error.h> */
#define PSA_ERROR_INSUFFICIENT_ENTROPY  ((psa_status_t)-148)  /* Defined in <psa/crypto.h> */
#define PSA_ERROR_INVALID_SIGNATURE     ((psa_status_t)-149)  /* Defined in <psa/error.h> */
#define PSA_ERROR_INVALID_PADDING       ((psa_status_t)-150)  /* Defined in <psa/crypto.h> */
#define PSA_ERROR_CORRUPTION_DETECTED   ((psa_status_t)-151)  /* Defined in <psa/crypto.h> */
#define PSA_ERROR_DATA_CORRUPT          ((psa_status_t)-152)  /* Defined in <psa/storage.h> and <psa/crypto.h> */
#define PSA_ERROR_DATA_INVALID          ((psa_status_t)-153)  /* Defined in <psa/crypto.h> */
#define PSA_ERROR_ROLLBACK_DETECTED     ((psa_status_t)-154)  /* Defined in <psa/update.h> */
#define PSA_ERROR_WRONG_DEVICE          ((psa_status_t)-155)  /* Defined in <psa/update.h> */
#define PSA_ERROR_DEPENDENCY_NEEDED     ((psa_status_t)-156)  /* Defined in <psa/update.h> */
#define PSA_ERROR_CURRENTLY_INSTALLING  ((psa_status_t)-157)  /* Defined in <psa/update.h> */
#define PSA_ERROR_ALREADY_INSTALLED     ((psa_status_t)-158)  /* Defined in <psa/update.h> */
#define PSA_ERROR_INSTALL_INTERRUPTED   ((psa_status_t)-159)  /* Defined in <psa/update.h> */
#define PSA_ERROR_FLASH_ABUSE           ((psa_status_t)-160)  /* Defined in <psa/update.h> */
#define PSA_ERROR_INSUFFICIENT_POWER    ((psa_status_t)-161)  /* Defined in <psa/update.h> */
#define PSA_ERROR_DECRYPTION_FAILURE    ((psa_status_t)-162)  /* Defined in <psa/update.h> */
#define PSA_ERROR_MISSING_MANIFEST      ((psa_status_t)-163)  /* Defined in <psa/update.h> */
#define PSA_ERROR_164                   ((psa_status_t)-164)  /* Reserved */
#define PSA_ERROR_165                   ((psa_status_t)-165)  /* Reserved */
#define PSA_ERROR_166                   ((psa_status_t)-166)  /* Reserved */
#define PSA_ERROR_167                   ((psa_status_t)-167)  /* Reserved */
#define PSA_ERROR_168                   ((psa_status_t)-168)  /* Reserved */
#define PSA_ERROR_169                   ((psa_status_t)-169)  /* Reserved */
#define PSA_ERROR_170                   ((psa_status_t)-170)  /* Reserved */
#define PSA_ERROR_171                   ((psa_status_t)-171)  /* Reserved */
#define PSA_ERROR_172                   ((psa_status_t)-172)  /* Reserved */
#define PSA_ERROR_173                   ((psa_status_t)-173)  /* Reserved */
#define PSA_ERROR_174                   ((psa_status_t)-174)  /* Reserved */
#define PSA_ERROR_175                   ((psa_status_t)-175)  /* Reserved */
#define PSA_ERROR_176                   ((psa_status_t)-176)  /* Reserved */
#define PSA_ERROR_177                   ((psa_status_t)-177)  /* Reserved */
#define PSA_ERROR_178                   ((psa_status_t)-178)  /* Reserved */
#define PSA_ERROR_179                   ((psa_status_t)-179)  /* Reserved */
#define PSA_ERROR_180                   ((psa_status_t)-180)  /* Reserved */
#define PSA_ERROR_181                   ((psa_status_t)-181)  /* Reserved */
#define PSA_ERROR_182                   ((psa_status_t)-182)  /* Reserved */
#define PSA_ERROR_183                   ((psa_status_t)-183)  /* Reserved */
#define PSA_ERROR_184                   ((psa_status_t)-184)  /* Reserved */
#define PSA_ERROR_185                   ((psa_status_t)-185)  /* Reserved */
#define PSA_ERROR_186                   ((psa_status_t)-186)  /* Reserved */
#define PSA_ERROR_187                   ((psa_status_t)-187)  /* Reserved */
#define PSA_ERROR_188                   ((psa_status_t)-188)  /* Reserved */
#define PSA_ERROR_189                   ((psa_status_t)-189)  /* Reserved */
#define PSA_ERROR_190                   ((psa_status_t)-190)  /* Reserved */
#define PSA_ERROR_191                   ((psa_status_t)-191)  /* Reserved */
#define PSA_ERROR_192                   ((psa_status_t)-192)  /* Reserved */
#define PSA_ERROR_193                   ((psa_status_t)-193)  /* Reserved */
#define PSA_ERROR_194                   ((psa_status_t)-194)  /* Reserved */
#define PSA_ERROR_195                   ((psa_status_t)-195)  /* Reserved */
#define PSA_ERROR_196                   ((psa_status_t)-196)  /* Reserved */
#define PSA_ERROR_197                   ((psa_status_t)-197)  /* Reserved */
#define PSA_ERROR_198                   ((psa_status_t)-198)  /* Reserved */
#define PSA_ERROR_199                   ((psa_status_t)-199)  /* Reserved */
#define PSA_ERROR_200                   ((psa_status_t)-200)  /* Reserved */
#define PSA_ERROR_201                   ((psa_status_t)-201)  /* Reserved */
#define PSA_ERROR_202                   ((psa_status_t)-202)  /* Reserved */
#define PSA_ERROR_203                   ((psa_status_t)-203)  /* Reserved */
#define PSA_ERROR_204                   ((psa_status_t)-204)  /* Reserved */
#define PSA_ERROR_205                   ((psa_status_t)-205)  /* Reserved */
#define PSA_ERROR_206                   ((psa_status_t)-206)  /* Reserved */
#define PSA_ERROR_207                   ((psa_status_t)-207)  /* Reserved */
#define PSA_ERROR_208                   ((psa_status_t)-208)  /* Reserved */
#define PSA_ERROR_209                   ((psa_status_t)-209)  /* Reserved */
#define PSA_ERROR_210                   ((psa_status_t)-210)  /* Reserved */
#define PSA_ERROR_211                   ((psa_status_t)-211)  /* Reserved */
#define PSA_ERROR_212                   ((psa_status_t)-212)  /* Reserved */
#define PSA_ERROR_213                   ((psa_status_t)-213)  /* Reserved */
#define PSA_ERROR_214                   ((psa_status_t)-214)  /* Reserved */
#define PSA_ERROR_215                   ((psa_status_t)-215)  /* Reserved */
#define PSA_ERROR_216                   ((psa_status_t)-216)  /* Reserved */
#define PSA_ERROR_217                   ((psa_status_t)-217)  /* Reserved */
#define PSA_ERROR_218                   ((psa_status_t)-218)  /* Reserved */
#define PSA_ERROR_219                   ((psa_status_t)-219)  /* Reserved */
#define PSA_ERROR_220                   ((psa_status_t)-220)  /* Reserved */
#define PSA_ERROR_221                   ((psa_status_t)-221)  /* Reserved */
#define PSA_ERROR_222                   ((psa_status_t)-222)  /* Reserved */
#define PSA_ERROR_223                   ((psa_status_t)-223)  /* Reserved */
#define PSA_ERROR_224                   ((psa_status_t)-224)  /* Reserved */
#define PSA_ERROR_225                   ((psa_status_t)-225)  /* Reserved */
#define PSA_ERROR_226                   ((psa_status_t)-226)  /* Reserved */
#define PSA_ERROR_227                   ((psa_status_t)-227)  /* Reserved */
#define PSA_ERROR_228                   ((psa_status_t)-228)  /* Reserved */
#define PSA_ERROR_229                   ((psa_status_t)-229)  /* Reserved */
#define PSA_ERROR_230                   ((psa_status_t)-230)  /* Reserved */
#define PSA_ERROR_231                   ((psa_status_t)-231)  /* Reserved */
#define PSA_ERROR_232                   ((psa_status_t)-232)  /* Reserved */
#define PSA_ERROR_233                   ((psa_status_t)-233)  /* Reserved */
#define PSA_ERROR_234                   ((psa_status_t)-234)  /* Reserved */
#define PSA_ERROR_235                   ((psa_status_t)-235)  /* Reserved */
#define PSA_ERROR_236                   ((psa_status_t)-236)  /* Reserved */
#define PSA_ERROR_237                   ((psa_status_t)-237)  /* Reserved */
#define PSA_ERROR_238                   ((psa_status_t)-238)  /* Reserved */
#define PSA_ERROR_239                   ((psa_status_t)-239)  /* Reserved */
#define PSA_ERROR_240                   ((psa_status_t)-240)  /* Reserved */
#define PSA_ERROR_241                   ((psa_status_t)-241)  /* Reserved */
#define PSA_ERROR_242                   ((psa_status_t)-242)  /* Reserved */
#define PSA_ERROR_243                   ((psa_status_t)-243)  /* Reserved */
#define PSA_ERROR_244                   ((psa_status_t)-244)  /* Reserved */
#define PSA_ERROR_245                   ((psa_status_t)-245)  /* Reserved */
#define PSA_ERROR_246                   ((psa_status_t)-246)  /* Reserved */
#define PSA_ERROR_247                   ((psa_status_t)-247)  /* Reserved */
#define PSA_ERROR_248                   ((psa_status_t)-248)  /* Reserved */
#define PSA_ERROR_SPM_IMP_0             ((psa_status_t)-249)  /* Reserved for SPM implementation specific use */
#define PSA_ERROR_SPM_IMP_1             ((psa_status_t)-250)  /* Reserved for SPM implementation specific use */
#define PSA_ERROR_SPM_IMP_2             ((psa_status_t)-251)  /* Reserved for SPM implementation specific use */
#define PSA_ERROR_SPM_IMP_3             ((psa_status_t)-252)  /* Reserved for SPM implementation specific use */
#define PSA_ERROR_SPM_IMP_4             ((psa_status_t)-253)  /* Reserved for SPM implementation specific use */
#define PSA_ERROR_SPM_IMP_5             ((psa_status_t)-254)  /* Reserved for SPM implementation specific use */
#define PSA_ERROR_SPM_IMP_6             ((psa_status_t)-255)  /* Reserved for SPM implementation specific use */
#define PSA_ERROR_SPM_IMP_7             ((psa_status_t)-256)  /* Reserved for SPM implementation specific use */
