"""
NAS/RRC Headers for Cellular Network Security Detection
Specification-based Intrusion Detection for 4G/5G Networks

Structure:
- Single continuous global numbering (1–366) across all protocol types
- No tier-based number resets or overlaps
- Protocol-organized with NAS then RRC sections
- Use FEATURE_ID dictionary for accessing field indices programmatically
"""

nas_rrc_headers_ai = [
    # ============================================================================
    # NAS-EPS SECTION (IDs 1–166)
    # ============================================================================
    
    # Tier 1: Critical Attack Indicators (IDs 1–20)
    'gsm_a_dtap_autn',                    # Authentication token used in GSM
    'gsm_a_dtap_rand',                    # Random challenge for authentication
    'nas-eps_msg_auth_code',              # Message authentication code for NAS-EPS
    'nas-eps_seq_no',                     # Sequence number for NAS-EPS messages
    'e212_mcc',                           # Mobile Country Code for E.212
    'e212_mnc',                           # Mobile Network Code for E.212
    'nas-eps_emm_mme_code',               # MME identifier in NAS-EPS
    'nas-eps_emm_mme_grp_id',             # MME group identifier in NAS-EPS
    'nas-eps_security_header_type',       # Type of security protection level in NAS-EPS
    'nas-eps_emm_nas_key_set_id',         # Key set identifier for NAS-EPS
    'nas-eps_emm_cause',                  # Reasons for EMM failure in NAS-EPS
    'nas-eps_emm_tai_tac',                # Tracking Area Code in NAS-EPS
    'e212_gummei_mcc',                    # GUMMEI Mobile Country Code
    'e212_gummei_mnc',                    # GUMMEI Mobile Network Code
    'nas-eps_nas_msg_emm_type',           # Type of EMM message in NAS-EPS
    'gsm_a_dtap_autn_sqn_xor_ak',         # Sequence number in AUTN XORed with AK
    'nas-eps_emm_short_mac',              # Short Message Authentication Code in NAS-EPS
    'nas-eps_emm_tsc',                    # Type of security context in NAS-EPS
    'e212_tai_mcc',                       # TAI Mobile Country Code
    'e212_tai_mnc',                       # TAI Mobile Country Code

    # Tier 2: High Priority Detection (IDs 21–61)
    'nas-eps_emm_res',                    # Authentication response in NAS-EPS
    'gsm_a_dtap_autn_mac',                # Message Authentication Code in AUTN
    'nas-eps_emm_type_of_id',             # Type of identity in NAS-EPS
    'nas-eps_emm_m_tmsi',                 # Temporary Mobile Subscriber Identity in NAS-EPS
    'nas-eps_emm_guti_type',              # Type of GUTI in NAS-EPS
    'nas-eps_emm_eps_att_type',           # Attach type in NAS-EPS
    'nas-eps_emm_detach_type_ul',         # Detach type in NAS-EPS uplink
    'nas-eps_emm_update_type_value',      # Update type in NAS-EPS
    'nas-eps_emm_detach_req_ul',          # Detach request uplink in NAS-EPS
    'gsm_a_l3_protocol_discriminator',    # Protocol discriminator in GSM Layer 3
    'nas-eps_emm_tai_n_elem',             # Number of TAI elements in NAS-EPS
    'nas-eps_emm_tai_tol',                # Type of list in NAS-EPS
    'gsm_a_lac',                          # Location Area Code in GSM
    'nas-eps_esm_cause',                  # Reasons for ESM failure in NAS-EPS
    'nas-eps_emm_active_flg',             # Active flag in NAS-EPS
    'nas-eps_emm_switch_off',             # Switch off indicator in NAS-EPS
    'nas-eps_seq_no_short',               # Short sequence number in NAS-EPS
    'nas-eps_spare_bits',                 # Spare bits in NAS-EPS
    'nas-eps_nas_msg_esm_type',           # ESM message type in NAS-EPS
    'nas-eps_emm_odd_even',               # Odd/even indicator in NAS-EPS
    'e212_imsi',                          # International Mobile Subscriber Identity
    'gsm_a_dtap_autn_amf',                # Authentication Management Field in AUTN
    'nas-eps_bearer_id',                  # Bearer ID in NAS-EPS
    'nas-eps_esm_proc_trans_id',          # Procedure transaction ID in NAS-EPS
    'nas-eps_emm_eps_attach_result',      # Attach result in NAS-EPS
    'nas-eps_emm_eps_update_result_value', # Update result in NAS-EPS
    'nas-eps_emm_ims_vops',               # IMS Voice over PS in NAS-EPS
    'nas-eps_emm_epc_lcs',                # EPC Location Services in NAS-EPS
    'nas-eps_emm_cp_ciot',                # Control Plane CIoT in NAS-EPS
    'nas-eps_emm_up_ciot',                # User Plane CIoT in NAS-EPS
    'nas-eps_emm_hc_cp_ciot',             # High Capacity Control Plane CIoT in NAS-EPS
    'nas-eps_emm_s1_u_data',              # S1-U data in NAS-EPS

    # Tier 3: Medium Priority (IDs 62–108)
    'nas-eps_emm_cp_ciot_cap',            # Control Plane CIoT capability in NAS-EPS
    'nas-eps_emm_up_ciot_cap',            # User Plane CIoT capability in NAS-EPS
    'nas-eps_emm_hc_cp_ciot_cap',         # High Capacity Control Plane CIoT capability in NAS-EPS
    'nas-eps_emm_s1u_data_cap',           # S1-U data capability in NAS-EPS
    'nas-eps_emm_er_wo_pdn',              # Emergency Registration without PDN in NAS-EPS
    'nas-eps_emm_er_wo_pdn_cap',          # Emergency Registration without PDN capability in NAS-EPS
    'nas-eps_emm_dcnr_cap',               # DCNR capability in NAS-EPS
    'nas-eps_emm_n1mode_cap',             # N1 mode capability in NAS-EPS
    'nas-eps_emm_restrict_dcnr',          # Restriction on DCNR in NAS-EPS
    'nas-eps_emm_restrict_ec',            # Restriction on EC in NAS-EPS
    'nas-eps_emm_restrict_ec_cap',        # Restriction on EC capability in NAS-EPS
    'nas-eps_emm_15_bearers',             # Support for 15 bearers in NAS-EPS
    'nas-eps_emm_15_bearers_cap',         # Capability for 15 bearers in NAS-EPS
    'nas-eps_emm_cp_backoff_cap',         # Control Plane backoff capability in NAS-EPS
    'nas-eps_emm_multiple_drb_cap',       # Multiple DRB capability in NAS-EPS
    'nas-eps_emm_1xsrvcc_cap',            # 1xSRVCC capability in NAS-EPS
    'nas-eps_emm_acc_csfb_cap',           # Access CSFB capability in NAS-EPS
    'nas-eps_emm_lcs_cap',                # Location Services capability in NAS-EPS
    'nas-eps_emm_lpp_cap',                # LPP capability in NAS-EPS
    'nas-eps_emm_cs_lcs',                 # Circuit Switched Location Services in NAS-EPS
    'nas-eps_emm_emc_bs',                 # Emergency Bearer Services in NAS-EPS
    'nas-eps_emm_epco',                   # EPCO in NAS-EPS
    'nas-eps_emm_epco_cap',               # EPCO capability in NAS-EPS
    'nas-eps_emm_prose_cap',              # ProSe capability in NAS-EPS
    'nas-eps_emm_prose_dc_cap',           # ProSe Direct Communication capability in NAS-EPS
    'nas-eps_emm_prose_dd_cap',           # ProSe Direct Discovery capability in NAS-EPS
    'nas-eps_emm_prose_relay_cap',        # ProSe Relay capability in NAS-EPS
    'nas-eps_emm_v2x_pc5_cap',            # V2X PC5 capability in NAS-EPS
    'nas-eps_emm_sgc_cap',                # SGC capability in NAS-EPS
    'nas-eps_emm_nf_cap',                 # NF capability in NAS-EPS
    'nas-eps_emm_h245_ash_cap',           # H.245 ASH capability in NAS-EPS
    'nas-eps_emm_iwkn26',                 # IWKN26 in NAS-EPS
    'nas-eps_emm_esr_ps',                 # ESR for PS in NAS-EPS
    'nas-eps_emm_ue_ra_cap_inf_upd_need_flg', # UE RA capability information update needed flag in NAS-EPS
    'nas-eps_emm_emm_ucs2_supp',          # UCS2 support in NAS-EPS
    'nas-eps_emm_spare_half_octet',       # Spare half octet in NAS-EPS
    'nas-eps_emm_toc',                    # Type of Ciphering in NAS-EPS
    'nas-eps_emm_toi',                    # Type of Integrity in NAS-EPS
    'nas-eps_emm_imeisv_req',             # IMEISV request in NAS-EPS
    'nas-eps_emm_hash_mme',               # Hash of MME in NAS-EPS
    'nas-eps_emm_replayed_nas_msg_cont',  # Replayed NAS message content in NAS-EPS
    'nas-eps_emm_esm_msg_cont',           # ESM message content in NAS-EPS
    'gsm_a_ie_mobileid_type',             # Mobile ID type in GSM
    'gsm_a_oddevenind',                   # Odd/even indicator in GSM
    'gsm_a_imeisv',                       # IMEISV in GSM
    'gsm_a_key_seq',                      # Key sequence in GSM
    'gsm_a_skip_ind',                     # Skip indicator in GSM

    # Tier 4: Supporting Fields – Encryption & Integrity Algorithms (IDs 109–155)
    'nas-eps_emm_eea0',                   # Encryption algorithm 0 in NAS-EPS
    'nas-eps_emm_eea3',                   # Encryption algorithm 3 in NAS-EPS
    'nas-eps_emm_eea4',                   # Encryption algorithm 4 in NAS-EPS
    'nas-eps_emm_eea5',                   # Encryption algorithm 5 in NAS-EPS
    'nas-eps_emm_eea6',                   # Encryption algorithm 6 in NAS-EPS
    'nas-eps_emm_eea7',                   # Encryption algorithm 7 in NAS-EPS
    'nas-eps_emm_eia0',                   # Integrity algorithm 0 in NAS-EPS
    'nas-eps_emm_eia3',                   # Integrity algorithm 3 in NAS-EPS
    'nas-eps_emm_eia4',                   # Integrity algorithm 4 in NAS-EPS
    'nas-eps_emm_eia5',                   # Integrity algorithm 5 in NAS-EPS
    'nas-eps_emm_eia6',                   # Integrity algorithm 6 in NAS-EPS
    'nas-eps_emm_5g_ea0',                 # 5G encryption algorithm 0
    'nas-eps_emm_5g_ea4',                 # 5G encryption algorithm 4
    'nas-eps_emm_5g_ea5',                 # 5G encryption algorithm 5
    'nas-eps_emm_5g_ea6',                 # 5G encryption algorithm 6
    'nas-eps_emm_5g_ea7',                 # 5G encryption algorithm 7
    'nas-eps_emm_5g_ea8',                 # 5G encryption algorithm 8
    'nas-eps_emm_5g_ea9',                 # 5G encryption algorithm 9
    'nas-eps_emm_5g_ea10',                # 5G encryption algorithm 10
    'nas-eps_emm_5g_ea11',                # 5G encryption algorithm 11
    'nas-eps_emm_5g_ea12',                # 5G encryption algorithm 12
    'nas-eps_emm_5g_ea13',                # 5G encryption algorithm 13
    'nas-eps_emm_5g_ea14',                # 5G encryption algorithm 14
    'nas-eps_emm_5g_ea15',                # 5G encryption algorithm 15
    'nas-eps_emm_5g_ia0',                 # 5G integrity algorithm 0
    'nas-eps_emm_5g_ia4',                 # 5G integrity algorithm 4
    'nas-eps_emm_5g_ia5',                 # 5G integrity algorithm 5
    'nas-eps_emm_5g_ia6',                 # 5G integrity algorithm 6
    'nas-eps_emm_5g_ia7',                 # 5G integrity algorithm 7
    'nas-eps_emm_5g_ia8',                 # 5G integrity algorithm 8
    'nas-eps_emm_5g_ia9',                 # 5G integrity algorithm 9
    'nas-eps_emm_5g_ia10',                # 5G integrity algorithm 10
    'nas-eps_emm_5g_ia11',                # 5G integrity algorithm 11
    'nas-eps_emm_5g_ia12',                # 5G integrity algorithm 12
    'nas-eps_emm_5g_ia13',                # 5G integrity algorithm 13
    'nas-eps_emm_5g_ia14',                # 5G integrity algorithm 14
    'nas-eps_emm_5g_ia15',                # 5G integrity algorithm 15
    'nas-eps_emm_128_5g_ea1',             # 128-bit 5G encryption algorithm 1
    'nas-eps_emm_128_5g_ea2',             # 128-bit 5G encryption algorithm 2
    'nas-eps_emm_128_5g_ea3',             # 128-bit 5G encryption algorithm 3
    'nas-eps_emm_128_5g_ia1',             # 128-bit 5G integrity algorithm 1
    'nas-eps_emm_128_5g_ia2',             # 128-bit 5G integrity algorithm 2
    'nas-eps_emm_128_5g_ia3',             # 128-bit 5G integrity algorithm 3
    'nas-eps_emm_128eea1',                # 128-bit EEA1 encryption algorithm
    'nas-eps_emm_128eea2',                # 128-bit EEA2 encryption algorithm
    'nas-eps_emm_128eia1',                # 128-bit EIA1 integrity algorithm
    'nas-eps_emm_128eia2',                # 128-bit EIA2 integrity algorithm

    # Tier 5: Bearer & ESM Fields (IDs 156–166)
    'nas-eps_emm_eps_upip',               # EPS User Plane IP
    'nas-eps_esm_apn_ambr_dl',            # APN Aggregate Maximum Bit Rate for downlink
    'nas-eps_esm_apn_ambr_ul',            # APN Aggregate Maximum Bit Rate for uplink
    'nas-eps_esm_apn_ambr_dl_ext',        # Extended APN AMBR for downlink
    'nas-eps_esm_apn_ambr_ul_ext',        # Extended APN AMBR for uplink
    'nas-eps_esm_apn_ambr_dl_ext2',       # Second extension of APN AMBR for downlink
    'nas-eps_esm_apn_ambr_ul_ext2',       # Second extension of APN AMBR for uplink
    'nas-eps_esm_apn_ambr_dl_total',      # Total APN AMBR for downlink
    'nas-eps_esm_apn_ambr_ul_total',      # Total APN AMBR for uplink
    'nas-eps_esm_pdn_type',               # PDN type in NAS-EPS
    'nas-eps_esm_request_type',           # Request type in NAS-EPS

    # ============================================================================
    # RRC SECTION (IDs 167–366)
    # ============================================================================

    # Tier 1: Critical Cell Identity & Signal (LTE) (IDs 167–191)
    'lte-rrc_physcellid',                 # Physical cell ID
    'lte-rrc_cellidentity',               # Cell identity
    'lte-rrc_mcc',                        # Mobile Country Code
    'lte-rrc_mnc',                        # Mobile Network Code
    'lte-rrc_trackingareacode',           # Tracking area
    'lte-rrc_rsrpresult_r9',              # Signal strength
    'lte-rrc_rsrqresult_r9',              # Signal quality
    'lte-rrc_referencesignalpower',       # Reference signal power
    'lte-rrc_carrierfreq',                # Carrier frequency
    'lte-rrc_dl_carrierfreq',             # Downlink frequency
    'lte-rrc_establishmentcause',         # Connection cause
    'lte-rrc_reestablishmentcause',       # Reestablishment cause
    'lte-rrc_releasecause',               # Release cause
    'lte-rrc_connectionfailuretype_r10',  # Failure type
    'lte-rrc_rlf_cause_r11',              # Radio link failure
    'lte-rrc_freqbandindicator',          # Frequency band
    'lte-rrc_cipheringalgorithm',         # Encryption algorithm
    'lte-rrc_integrityprotalgorithm',     # Integrity algorithm
    'lte-rrc_shortmac_i',                 # Short MAC-I
    'lte-rrc_nexthopchainingcount',       # Security hop count
    'lte-rrc_connestfailcount_r12',       # Connection failure count
    'lte-rrc_rach_report_r9',             # Random access report
    'lte-rrc_mobilitystate_r12',          # Mobility state
    'lte-rrc_ul_carrierfreq',             # Uplink frequency
    'lte-rrc_selectedplmn_identity',      # Selected PLMN

    # Tier 2: NR/5G Critical Fields (IDs 192–206)
    'nr-rrc_cellidentity',                # NR cell identity
    'nr-rrc_mcc',                         # NR MCC
    'nr-rrc_mnc',                         # NR MNC
    'nr-rrc_trackingareacode',            # NR tracking area
    'nr-rrc_ss_pbch_blockpower',          # NR signal power
    'nr-rrc_q_rxlevmin',                  # NR minimum signal level
    'nr-rrc_carrierbandwidth',            # NR bandwidth
    'nr-rrc_freqbandindicatornr',         # NR frequency band
    'nr-rrc_subcarrierspacing',           # NR subcarrier spacing
    'nr-rrc_subcarrierspacingcommon',     # NR common subcarrier spacing
    'nr-rrc_offsettocarrier',             # NR carrier offset
    'nr-rrc_offsettopointa',              # NR point A offset
    'nr-rrc_referencesubcarrierspacing',  # NR reference SCS
    'nr-rrc_ssb_subcarrieroffset',        # NR SSB subcarrier offset
    'nr-rrc_locationandbandwidth',        # NR location and bandwidth

    # Tier 3: LTE Configuration & Performance (IDs 214–253)
    'lte-rrc_timesincefailure_r11',       # Time since failure
    'lte-rrc_rlf_infoavailable_r10',      # RLF info available
    'lte-rrc_q_rxlevmin',                 # LTE minimum signal level
    'lte-rrc_dl_bandwidth',               # LTE DL bandwidth
    'lte-rrc_ul_bandwidth',               # LTE UL bandwidth
    'lte-rrc_transmissionmode',           # Transmission mode
    'lte-rrc_accessstratumrelease',       # Access stratum release
    'lte-rrc_ue_category',                # UE category
    'lte-rrc_supportedbandlisteutra',     # Supported band list
    'lte-rrc_interfreqneedforgaps',       # Inter-freq gaps needed
    'lte-rrc_interrat_needforgaps',       # Inter-RAT gaps needed
    'lte-rrc_loggedmeasurementsidle_r10', # Logged measurements
    'lte-rrc_ims_emergencysupport_r9',    # Emergency support
    'lte-rrc_en_dc_r15',                  # EN-DC support
    'lte-rrc_dl_256qam_r12',              # 256QAM DL support
    'lte-rrc_ul_64qam_r12',               # 64QAM UL support
    'lte-rrc_ul_256qam_r14',              # 256QAM UL support
    'lte-rrc_enable64qam',                # 64QAM enabled
    'lte-rrc_alternativetbs_indices_r12', # Alternative TBS indices
    'lte-rrc_halfduplex',                 # Half duplex support
    'lte-rrc_ue_category_v1020',          # UE category v10.2.0
    'lte-rrc_ue_category_v1170',          # UE category v11.7.0
    'lte-rrc_ue_categorydl_r12',          # UE category DL
    'lte-rrc_ue_categoryul_r12',          # UE category UL
    'lte-rrc_systemframenumber',          # System frame number
    'lte-rrc_defaultpagingcycle',         # Default paging cycle
    'lte-rrc_neighcellconfig',            # Neighbor cell config
    'lte-rrc_t300',                       # Timer T300
    'lte-rrc_t301',                       # Timer T301
    'lte-rrc_t310',                       # Timer T310
    'lte-rrc_t311',                       # Timer T311
    'lte-rrc_t320',                       # Timer T320
    'lte-rrc_n310',                       # Counter N310
    'lte-rrc_n311',                       # Counter N311
    'lte-rrc_p_max',                      # Maximum power
    'lte-rrc_alpha',                      # Alpha parameter
    'lte-rrc_p0_nominalpusch',            # P0 nominal PUSCH
    'lte-rrc_p0_nominalpucch',            # P0 nominal PUCCH
    'lte-rrc_deltaf_pucch_format1',       # Delta F PUCCH format 1
    'lte-rrc_deltaf_pucch_format1b',      # Delta F PUCCH format 1b

    # Tier 4: System Information & Configuration (IDs 254–308)
    'lte-rrc_schedulinginfolist',         # Scheduling info list
    'lte-rrc_si_windowlength',            # SI window length
    'lte-rrc_systeminfovaluetag',         # System info value tag
    'lte-rrc_cellbarred',                 # Cell barred
    'lte-rrc_cellreservedforoperatoruse', # Cell reserved
    'lte-rrc_intrafreqreselection',       # Intra-freq reselection
    'lte-rrc_q_hyst',                     # Q hysteresis
    'lte-rrc_s_intrasearch',              # S intra search
    'lte-rrc_s_nonintrasearch',           # S non-intra search
    'lte-rrc_threshservinglow',           # Threshold serving low
    'lte-rrc_cellreselectionpriority',    # Cell reselection priority
    'lte-rrc_q_offsetfreq',               # Q offset freq
    'lte-rrc_threshx_high',               # Threshold X high
    'lte-rrc_threshx_low',                # Threshold X low
    'lte-rrc_t_reselectioneutra',         # T reselection EUTRA
    'nr-rrc_defaultpagingcycle',          # NR default paging cycle
    'nr-rrc_modificationperiodcoeff',     # NR modification period
    'nr-rrc_ssb_periodicityservingcell',  # NR SSB periodicity
    'nr-rrc_dmrs_typea_position',         # NR DMRS Type A position
    'nr-rrc_systemframenumber',           # NR system frame number
    'nr-rrc_t300',                        # NR Timer T300
    'nr-rrc_t301',                        # NR Timer T301
    'nr-rrc_t310',                        # NR Timer T310
    'nr-rrc_t311',                        # NR Timer T311
    'nr-rrc_t319',                        # NR Timer T319
    'nr-rrc_n310',                        # NR Counter N310
    'nr-rrc_n311',                        # NR Counter N311
    'lte-rrc_rrc_transactionidentifier',  # RRC transaction ID
    'lte-rrc_c_rnti',                     # C-RNTI
    'lte-rrc_randomvalue',                # Random value
    'lte-rrc_ue_identity',                # UE identity
    'lte-rrc_m_tmsi',                     # M-TMSI
    'lte-rrc_mmec',                       # MME code
    'lte-rrc_mmegi',                      # MME group ID
    'lte-rrc_eps_beareridentity',         # EPS bearer identity
    'lte-rrc_drb_identity',               # DRB identity
    'lte-rrc_srb_identity',               # SRB identity
    'lte-rrc_logicalchannelidentity',     # Logical channel identity
    'lte-rrc_gummei_type_r10',            # GUMMEI type
    'lte-rrc_rat_type',                   # RAT type
    'lte-rrc_cn_domain',                  # CN domain
    'lte-rrc_failedpcellid_r10',          # Failed PCell ID
    'lte-rrc_tac_failedpcell_r12',        # TAC of failed PCell
    'lte-rrc_rlf_reportreq_r9',           # RLF report request
    'lte-rrc_rach_reportreq_r9',          # RACH report request
    'lte-rrc_rlf_infoavailable_r9',       # RLF info available R9
    'lte-rrc_connestfailoffsetvalidity_r12', # Connection establishment failure offset
    'lte-rrc_latenoncriticalextension',   # Late non-critical extension
    'lte-rrc_criticalextensions',         # Critical extensions
    'lte-rrc_c1',                         # C1 choice
    'lte-rrc_dl_ccch_message_message',    # DL CCCH message
    'lte-rrc_dl_dcch_message_message',    # DL DCCH message
    'lte-rrc_ul_ccch_message_message',    # UL CCCH message
    'lte-rrc_ul_dcch_message_message',    # UL DCCH message
    'lte-rrc_pcch_message_message',       # PCCH message

    # Tier 5: Advanced Features & Configuration (IDs 309–346)
    'lte-rrc_dedicatedinfonas',           # Dedicated info NAS
    'lte-rrc_dedicatedinfotype',          # Dedicated info type
    'lte-rrc_dedicatedinfonaslist',       # Dedicated info NAS list
    'lte-rrc_ue_capabilityrequest',       # UE capability request
    'lte-rrc_ue_capabilityrat_containerlist', # UE capability RAT container
    'lte-rrc_uecapabilityrat_container',  # UE capability RAT container
    'lte-rrc_featuregroupindicators',     # Feature group indicators
    'lte-rrc_interfreqcarrierfreqlist',   # Inter-freq carrier list
    'lte-rrc_interfreqbandlist',          # Inter-freq band list
    'lte-rrc_interrat_bandlist',          # Inter-RAT band list
    'lte-rrc_supportedbandgeran',         # Supported band GERAN
    'lte-rrc_supportedbandlistgeran',     # Supported band list GERAN
    'lte-rrc_supportedbandutra_fdd',      # Supported band UTRA FDD
    'lte-rrc_supportedbandlistutra_fdd',  # Supported band list UTRA FDD
    'lte-rrc_supportedbandcombination_r10', # Supported band combination
    'lte-rrc_supportedbandcombinationext_r10', # Supported band combination ext
    'lte-rrc_bandcombinationlisteutra_r10', # Band combination list EUTRA
    'lte-rrc_bandcombinationparameters_r10', # Band combination parameters
    'lte-rrc_ca_bandwidthclassdl_r10',    # CA bandwidth class DL
    'lte-rrc_ca_bandwidthclassul_r10',    # CA bandwidth class UL
    'lte-rrc_supportedmimo_capabilitydl_r10', # Supported MIMO capability DL
    'lte-rrc_ue_specificrefsigssupported', # UE specific ref signals
    'lte-rrc_ue_transmitantennaselection', # UE transmit antenna selection
    'lte-rrc_ue_txantennaselectionsupported', # UE TX antenna selection support
    'lte-rrc_maxharq_tx',                 # Max HARQ TX
    'lte-rrc_periodicbsr_timer',          # Periodic BSR timer
    'lte-rrc_retxbsr_timer',              # Retransmission BSR timer
    'lte-rrc_ttibundling',                # TTI bundling
    'lte-rrc_mac_mainconfig',             # MAC main config
    'lte-rrc_mac_contentionresolutiontimer', # MAC contention resolution timer
    'lte-rrc_maxharq_msg3tx',             # Max HARQ MSG3 TX
    'lte-rrc_n1pucch_an',                 # N1 PUCCH AN
    'lte-rrc_deltaf_pucch_format2',       # Delta F PUCCH format 2
    'lte-rrc_deltaf_pucch_format2a',      # Delta F PUCCH format 2a
    'lte-rrc_deltaf_pucch_format2b',      # Delta F PUCCH format 2b
    'lte-rrc_deltapucch_shift',           # Delta PUCCH shift

    # Tier 6: NR Advanced Configuration (IDs 347–366)
    'nr-rrc_schedulinginfolist',          # NR scheduling info list
    'nr-rrc_si_windowlength',             # NR SI window length
    'nr-rrc_si_periodicity',              # NR SI periodicity
    'nr-rrc_sib_mappinginfo',             # NR SIB mapping info
    'nr-rrc_valuetag',                    # NR value tag
    'nr-rrc_si_broadcaststatus',          # NR SI broadcast status
    'nr-rrc_cellbarred',                  # NR cell barred
    'nr-rrc_cellreservedforoperatoruse',  # NR cell reserved
    'nr-rrc_intrafreqreselection',        # NR intra-freq reselection
    'nr-rrc_plmn_identitylist',           # NR PLMN identity list
    'nr-rrc_plmn_identityinfolist',       # NR PLMN identity info list
    'nr-rrc_frequencybandlist',           # NR frequency band list
    'nr-rrc_scs_specificcarrierlist',     # NR SCS specific carrier list
    'nr-rrc_timealignmenttimercommon',    # NR time alignment timer
    'nr-rrc_rsrp_thresholdssb',           # NR RSRP threshold SSB
    'nr-rrc_rach_configcommon',           # NR RACH config common
    'nr-rrc_ra_responsewindow',           # NR RA response window
    'nr-rrc_ra_contentionresolutiontimer', # NR RA contention resolution
    'nr-rrc_powerrampingstep',            # NR power ramping step
    'nr-rrc_preamblereceivedtargetpower', # NR preamble received target power
    'nr-rrc_dl_dcch_message_message',    # NR DL DCCH message
    'nr-rrc_ul_dcch_message_message',    # NR UL DCCH message
    'nr-rrc_dl_ccch_message_message',    # NR DL CCCH message
    'nr-rrc_ul_ccch_message_message',    # NR UL CCCH message
]

