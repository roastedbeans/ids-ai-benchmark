nas_rrc_headers_spec = [
    # NAS Essential
    'nas-eps_nas_msg_emm_type',
    'nas-eps_security_header_type',
    'nas-eps_ciphered_msg',                       # Ciphered/protected NAS message content
    'nas-eps_msg_auth_code',
    'nas-eps_seq_no',
    'nas-eps_emm_cause',
    'nas-eps_esm_cause',
    'nas-eps_emm_m_tmsi',
    'nas-eps_emm_type_of_id',
    'nas-eps_emm_update_type_value',
    'nas-eps_emm_tai_tac',
    'nas-eps_emm_EPS_attach_result',              # Attach result (indicates successful attach/connection)
    'nas-eps_emm_eps_update_result_value',        # TAU update result (indicates UE remains connected)
    'e212_gummei_mcc',                            # GUMMEI MCC
    'e212_gummei_mnc',                            # GUMMEI MNC
    'e212_tai_mcc',                               # TAI MCC
    'e212_tai_mnc',                               # TAI MNC
    'gsm_a_L3_protocol_discriminator',            # Protocol discriminator (GSM L3)

    # RRC Essential
    'lte-rrc_mcc',                                # LTE MCC
    'lte-rrc_mnc',                                # LTE MNC
    'nr-rrc_mcc',                                 # NR MCC
    'nr-rrc_mnc',                                 # NR MNC
    
    # LTE RRC State Detection
    'lte-rrc_rrcConnectionSetup_element',           # Connection establishment
    'lte-rrc_rrcConnectionRelease_element',         # Connection release
    'lte-rrc_rrcConnectionReject_element',        # Connection rejection
    'lte-rrc_rrcConnectionReestablishment_element',   # Re-establishment

    # NR RRC State Detection
    'nr-rrc_setup_element',                          # NR connection setup
    'nr-rrc_rrcReject_element',                      # NR connection rejection (DoS / panic attack)
    'nr-rrc_rrcRelease_element',                     # NR connection release (stealthy disconnect)
    'nr-rrc_rrcResume_element',                      # NR INACTIVE state resume

    # Connection Parameters
    'lte-rrc_waitTime',                             # Reject wait time (detect DoS)
    'lte-rrc_releaseCause',                         # Release reason validation
    'lte-rrc_reestablishmentCause',                 # Reestablishment reason
    
    # Cell Identification
    'lte-rrc_physCellId',                           # Physical cell ID
    'lte-rrc_cellIdentity',                         # Cell identity (28 bits)
    'lte-rrc_trackingAreaCode',                     # TAC validation
    'nr-rrc_cellIdentity',                          # NR cell identity
    'nr-rrc_trackingAreaCode',                      # NR TAC

    # System Information
    'lte-rrc_systemInfoValueTag',                   # SIB version tracking
    'lte-rrc_cellBarred',                           # Cell barring status
    'lte-rrc_cellReservedForOperatorUse',           # Cell reservation
    'nr-rrc_cellBarred',                            # NR cell barring
    
    # Security Mode Command Details
    'lte-rrc_cipheringAlgorithm',                   # EEA0-7 algorithm
    'lte-rrc_integrityProtAlgorithm',               # EIA0-7 algorithm
    'lte-rrc_securityConfigSMC_element',            # Security config container
    
    # Security Mode Command Container
    'lte-rrc_securityModeCommand_element',        # Security mode command container
    'lte-rrc_securityModeCommand_r8_element',    # Security mode command R8
    'lte-rrc_securityAlgorithmConfig_element',    # Algorithm config container
    
    # NAS Security Algorithms (boolean capability flags)
    'nas-eps_emm_eea0',                           # Null encryption capability
    'nas-eps_emm_eea3',                           # EEA3 capability
    'nas-eps_emm_128eea1',                        # 128-EEA1 capability
    'nas-eps_emm_128eea2',                        # 128-EEA2 capability
    'nas-eps_emm_eia0',                           # Null integrity capability
    'nas-eps_emm_eia3',                           # EIA3 capability
    'nas-eps_emm_128eia1',                        # 128-EIA1 capability
    'nas-eps_emm_128eia2',                        # 128-EIA2 capability

    # Security Context
    'lte-rrc_nextHopChainingCount',                 # NCC for key derivation
    'lte-rrc_shortMAC_I',                           # Short MAC-I validation
    
    # Measurement Configuration
    'lte-rrc_measId',                               # Measurement ID
    'lte-rrc_reportInterval',                       # Report interval
    'lte-rrc_measConfig_element',                   # Measurement config

    # Timers (TS 36.331 §7.3)
    'lte-rrc_t300',                                 # RRC connection timer (100-2000ms)
    'lte-rrc_t301',                                 # RRC reestablishment timer (100-2000ms)
    'lte-rrc_t310',                                 # Radio link failure timer (0-6000ms)
    'lte-rrc_t311',                                 # Reestablishment wait timer (1000-30000ms)
    'lte-rrc_t304',                                 # Handover timer

    # Counters
    'lte-rrc_n310',                                 # Out-of-sync count (1-20)
    'lte-rrc_n311',                                 # In-sync count (1-10)

    # NR Timers
    'nr-rrc_t300',                                 # NR RRC connection timer
    'nr-rrc_t310',                                 # NR radio link failure timer
    'nr-rrc_t311',                                 # NR reestablishment wait timer
    'nr-rrc_t319',                                 # NR INACTIVE state timer

    # Handover Configuration
    'lte-rrc_mobilityControlInfo_element',          # Handover command
    'lte-rrc_targetPhysCellId',                     # Target cell ID
    'lte-rrc_carrierFreq',                          # Target frequency
    'lte-rrc_dl_CarrierFreq',                       # DL carrier frequency

    # Mobility Measurements  
    'lte-rrc_cellReselectionPriority',             # Cell priority
    'lte-rrc_q_RxLevMin',                           # Minimum RX level
    'lte-rrc_threshServingLow',                     # Serving cell threshold

    # Paging Configuration
    'lte-rrc_defaultPagingCycle',                   # Paging cycle (32-256 frames)
    'lte-rrc_cn_Domain',                            # PS or CS domain
    'lte-rrc_pagingRecordList',                     # Number of paging records

    # UE Identity
    'lte-rrc_c_RNTI',                               # Cell RNTI
    'lte-rrc_ue_Identity_element',                  # UE identity container
    'lte-rrc_s_TMSI_element',                       # S-TMSI in paging
    'e212_imsi',                                    # IMSI value (identity capture detection)

    # Authentication Vectors (relay / replay attack detection)
    'gsm_a_dtap_rand',                              # RAND challenge (random nonce from network)
    'gsm_a_dtap_autn',                              # AUTN token (network authentication token)
    'gsm_a_dtap_autn_mac',                          # AUTN MAC field (replay: identical MAC = replayed)
    'gsm_a_dtap_autn_sqn_xor_ak',                  # SQN XOR AK (sequence number validation)
    'gsm_a_dtap_res',                               # RES (UE authentication response)

]
