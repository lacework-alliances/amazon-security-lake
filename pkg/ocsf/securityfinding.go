package ocsf

import (
	"time"
)

type SecurityFinding struct { //see https://schema.ocsf.io/classes/security_finding
	Activity           string                 `json:"activity" parquet:"name=activity, type=BYTE_ARRAY, convertedtype=UTF8"`
	ActivityID         int32                  `json:"activity_id" parquet:"name=activity_id, type=INT32"` //required
	Attacks            []Attack               `json:"attacks,omitempty" parquet:"name=attacks type=LIST"`
	Category           string                 `json:"category_name" parquet:"name=category_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	CategoryUID        int32                  `json:"category_uid" parquet:"name=category_uid, type=INT32"` //required
	Class              string                 `json:"class_name" parquet:"name=class_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	ClassUID           int32                  `json:"class_uid" parquet:"name=class_uid, type=INT32"` //required
	Compliance         ComplianceDetails      `json:"compliance,omitempty" parquet:"name=compliance"`
	Count              int32                  `json:"count,omitempty" parquet:"name=count, type=INT32"`
	Data               string                 `json:"data,omitempty" parquet:"name=data, type=BYTE_ARRAY, convertedtype=UTF8"`
	Duration           int32                  `json:"duration,omitempty" parquet:"name=duration, type=INT32"`
	EndTime            time.Time              `json:"end_time,omitempty" parquet:"name=end_time, type=TIMESTAMP_MILLIS"`
	EndTimeDT          time.Time              `json:"end_time_dt,omitempty" parquet:"name=end_time_dt, type=TIMESTAMP_MILLIS"`
	Enrichments        []Enrichment           `json:"enrichments,omitempty" parquet:"name=enrichments type=LIST"`
	EventTimeDT        time.Time              `json:"time_dt,omitempty" parquet:"name=time_dt, type=TIMESTAMP_MILLIS"`
	EventTime          time.Time              `json:"time" parquet:"name=time, type=TIMESTAMP_MILLIS"` //required
	Finding            FindingDetails         `json:"finding" parquet:"name=finding"`                  //required
	Malware            Malware                `json:"malware,omitempty" parquet:"name=malware"`
	Message            string                 `json:"message,omitempty" parquet:"name=message, type=BYTE_ARRAY, convertedtype=UTF8"` //recommended
	Metadata           Metadata               `json:"metadata" parquet:"name=metadata"`                                              //required
	Observables        Observable             `json:"observables,omitempty" parquet:"name=observables"`
	OriginalTime       string                 `json:"ref_time,omitempty" parquet:"name=ref_time, type=BYTE_ARRAY, convertedtype=UTF8"`
	Process            Process                `json:"process,omitempty" parquet:"name=process"`
	Profiles           []string               `json:"profiles,omitempty" parquet:"name=profiles, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	RawData            string                 `json:"raw_data,omitempty" parquet:"name=raw_data, type=BYTE_ARRAY, convertedtype=UTF8"`
	ReferenceEventCode string                 `json:"ref_event_code,omitempty" parquet:"name=ref_event_code, type=BYTE_ARRAY, convertedtype=UTF8"`
	ReferenceEventID   string                 `json:"ref_event_uid,omitempty" parquet:"name=ref_event_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	ReferenceEventName string                 `json:"ref_event_name,omitempty" parquet:"name=ref_event_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	ResourcesArray     []Resource             `json:"resources,omitempty" parquet:"name=resources type=LIST"` //recommended
	Severity           string                 `json:"severity" parquet:"name=severity, type=BYTE_ARRAY, convertedtype=UTF8"`
	SeverityID         SeverityID             `json:"severity_id" parquet:"name=severity_id"` //required
	StartTime          time.Time              `json:"start_time,omitempty" parquet:"name=start_time, type=TIMESTAMP_MILLIS"`
	State              string                 `json:"state,omitempty" parquet:"name=state, type=BYTE_ARRAY, convertedtype=UTF8"`
	StateID            int32                  `json:"state_id" parquet:"name=state_id, type=INT32"` //required
	Status             string                 `json:"status,omitempty" parquet:"name=status, type=BYTE_ARRAY, convertedtype=UTF8"`
	StatusCode         string                 `json:"status_code,omitempty" parquet:"name=status_code, type=BYTE_ARRAY, convertedtype=UTF8"`
	StatusDetail       string                 `json:"status_detail,omitempty" parquet:"name=status_detail, type=BYTE_ARRAY, convertedtype=UTF8"`
	StatusID           int32                  `json:"status_id,omitempty" parquet:"name=status_id, type=INT32"`             //recommended
	TimezoneOffset     int32                  `json:"timezone_offset,omitempty" parquet:"name=timezone_offset, type=INT32"` //recommended
	TypeID             int32                  `json:"type_uid" parquet:"name=type_uid, type=INT32"`                         //required             //required
	TypeName           string                 `json:"type_name,omitempty" parquet:"name=type_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	UnmappedData       string                 `json:"unmapped,omitempty" parquet:"name=unmapped, type=BYTE_ARRAY, convertedtype=UTF8"`
	Vulnerabilities    []VulnerabilityDetails `json:"vulnerabilities,omitempty" parquet:"name=vulnerabilities type=LIST"`
}

type Attack struct { //see https://schema.ocsf.io/objects/attack
	Profiles      []string `json:"profiles,omitempty" parquet:"name=profiles, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Tactics       []string `json:"technique_uid" parquet:"name=technique_uid, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	TechniqueID   string   `json:"attacks" parquet:"name=attacks, type=BYTE_ARRAY, convertedtype=UTF8"`
	TechniqueName string   `json:"technique_name" parquet:"name=technique_name, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type ComplianceDetails struct { //see https://schema.ocsf.io/objects/compliance
	Profiles      []string `json:"profiles,omitempty" parquet:"name=profiles, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Requirements  []string `json:"requirements,omitempty" parquet:"name=requirements, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Status        string   `json:"status,omitempty" parquet:"name=status, type=BYTE_ARRAY, convertedtype=UTF8"`
	StatusDetails string   `json:"status_detail,omitempty" parquet:"name=status_detail, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type Enrichment struct { //see https://schema.ocsf.io/objects/enrichment
	Data     string   `json:"data" parquet:"name=data, type=BYTE_ARRAY, convertedtype=UTF8"`
	Name     string   `json:"name" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Profiles []string `json:"profiles,omitempty" parquet:"name=profiles, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Provider string   `json:"provider,omitempty" parquet:"name=provider, type=BYTE_ARRAY, convertedtype=UTF8"`
	Type     string   `json:"type,omitempty" parquet:"name=type, type=BYTE_ARRAY, convertedtype=UTF8"`
	Value    string   `json:"value" parquet:"name=value, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type FindingDetails struct { //see https://schema.ocsf.io/objects/finding
	Confidence        int32             `json:"confidence,omitempty" parquet:"name=confidence, type=INT32"`
	CreatedTime       time.Time         `json:"created_time,omitempty" parquet:"name=created_time, type=TIMESTAMP_MILLIS"`
	CreatedTimeDT     time.Time         `json:"created_time_dt,omitempty" parquet:"name=created_time_dt, type=TIMESTAMP_MILLIS"`
	Description       string            `json:"desc,omitempty" parquet:"name=desc, type=BYTE_ARRAY, convertedtype=UTF8"`
	FirstSeenTime     time.Time         `json:"first_seen_time,omitempty" parquet:"name=first_seen_time, type=TIMESTAMP_MILLIS"`
	FirstSeenTimeDT   time.Time         `json:"first_seen_time_dt,omitempty" parquet:"name=first_seen_time_dt, type=TIMESTAMP_MILLIS"`
	LastSeenTime      time.Time         `json:"last_seen_time,omitempty" parquet:"name=last_seen_time, type=TIMESTAMP_MILLIS"`
	LastSeenTimeDT    time.Time         `json:"last_seen_time_dt,omitempty" parquet:"name=last_seen_time_dt, type=TIMESTAMP_MILLIS"`
	ModifiedTime      time.Time         `json:"modified_time,omitempty" parquet:"name=modified_time, type=TIMESTAMP_MILLIS"`
	ModifiedTimeDT    time.Time         `json:"modified_time_dt,omitempty" parquet:"name=modified_time_dt, type=TIMESTAMP_MILLIS"`
	ProductIdentifier string            `json:"product_uid,omitempty" parquet:"name=product_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	Profiles          []string          `json:"profiles,omitempty" parquet:"name=profiles, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	RelatedFindings   []RelatedFindings `json:"related_findings,omitempty" parquet:"name=related_findings type=LIST"`
	Remediation       Remediation       `json:"remediation,omitempty" parquet:"name=remediation"`
	SourceURL         string            `json:"src_url,omitempty" parquet:"name=src_url, type=BYTE_ARRAY, convertedtype=UTF8"`
	SupportingData    []string          `json:"supporting_data,omitempty" parquet:"name=supporting_data, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Title             string            `json:"title" parquet:"name=title, type=BYTE_ARRAY, convertedtype=UTF8"` //required
	Types             []string          `json:"types,omitempty" parquet:"name=types, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	UniqueID          string            `json:"uid" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"` //required
}

type Malware struct { //see https://schema.ocsf.io/objects/malware
	CVEUIDs           []string `json:"cve_uids,omitempty" parquet:"name=cve_uids, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	ClassificationIDs []int32  `json:"classification_ids" parquet:"name=classification_ids, type=LIST"`
	Classifications   []string `json:"classifications" parquet:"name=classifications, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Name              string   `json:"name" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Path              string   `json:"path,omitempty" parquet:"name=path, type=BYTE_ARRAY, convertedtype=UTF8"`
	Profiles          []string `json:"profiles,omitempty" parquet:"name=profiles, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Provider          string   `json:"provider,omitempty" parquet:"name=provider, type=BYTE_ARRAY, convertedtype=UTF8"`
	UniqueID          string   `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type Metadata struct { //see https://schema.ocsf.io/objects/metadata
	CorrelationUID string    `json:"correlation_uid,omitempty" parquet:"name=correlation_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	EventUID       string    `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	Labels         []string  `json:"labels,omitempty" parquet:"name=labels, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	LoggedTime     time.Time `json:"logged_time,omitempty" parquet:"name=logged_time, type=TIMESTAMP_MILLIS"`
	ModifiedTime   time.Time `json:"logged_time,omitempty" parquet:"name=logged_time, type=TIMESTAMP_MILLIS"`
	OriginalTime   time.Time `json:"original_time,omitempty" parquet:"name=original_time, type=TIMESTAMP_MILLIS"`
	ProcessedTime  time.Time `json:"processed_time,omitempty" parquet:"name=processed_time, type=TIMESTAMP_MILLIS"`
	Product        Product   `json:"product" parquet:"name=product"`
	Profiles       []string  `json:"profiles,omitempty" parquet:"name=profiles, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	SequenceNumber []int32   `json:"sequence,omitempty" parquet:"name=sequence, type=LIST"`
	Version        string    `json:"version" parquet:"name=version, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type Observable struct { //see https://schema.ocsf.io/objects/observable
	Name   string `json:"name" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Type   string `json:"type" parquet:"name=type, type=BYTE_ARRAY, convertedtype=UTF8"`
	TypeID int32  `json:"type_id" parquet:"name=confidence, type=INT32"`
	Value  string `json:"value,omitempty" parquet:"name=value, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type Process struct { //see https://schema.ocsf.io/objects/process
	CommandLine        string    `json:"cmd_line" parquet:"name=cmd_line, type=BYTE_ARRAY, convertedtype=UTF8"`
	CreatedTime        time.Time `json:"created_time,omitempty" parquet:"name=created_time, type=TIMESTAMP_MILLIS"`
	ExtendedAttributes string    `json:"xattributes,omitempty" parquet:"name=xattributes, type=BYTE_ARRAY, convertedtype=UTF8"`
	File               File      `json:"file,omitempty" parquet:"name=file"`
	Integrity          string    `json:"integrity,omitempty" parquet:"name=integrity, type=BYTE_ARRAY, convertedtype=UTF8"`
	IntegrityLevel     int32     `json:"integrity_id,omitempty" parquet:"name=integrity_id, type=INT32"`
	Lineage            []string  `json:"lineage,omitempty" parquet:"name=lineage, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	LoadedModules      []string  `json:"loaded_modules,omitempty" parquet:"name=loaded_modules, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Name               string    `json:"name,omitempty" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	ParentProcess      *Process  `json:"parent_process,omitempty" parquet:"name=parent_process type=INT64"`
	Path               string    `json:"path" parquet:"name=path, type=BYTE_ARRAY, convertedtype=UTF8"`
	ProcessID          int32     `json:"pid" parquet:"name=pid, type=INT32"`
	ProcessUID         int32     `json:"uid,omitempty" parquet:"name=uid, type=INT32"`
	RunAsUser          User      `json:"run_as,omitempty" parquet:"name=run_as"`
	Sandbox            string    `json:"sandbox,omitempty" parquet:"name=sandbox, type=BYTE_ARRAY, convertedtype=UTF8"`
	TerminatedTime     time.Time `json:"terminated_time,omitempty" parquet:"name=terminated_time, type=TIMESTAMP_MILLIS"`
	ThreadID           int32     `json:"tid,omitempty" parquet:"name=tid, type=INT32"`
}

type Resource struct { //see https://schema.ocsf.io/objects/resource
	AccountUID     int32    `json:"account_uid,omitempty" parquet:"name=account_uid, type=INT32"`
	CloudPartition string   `json:"cloud_partition,omitempty" parquet:"name=cloud_partition, type=BYTE_ARRAY, convertedtype=UTF8"`
	Criticality    string   `json:"criticality,omitempty" parquet:"name=criticality, type=BYTE_ARRAY, convertedtype=UTF8"`
	Details        string   `json:"details,omitempty" parquet:"name=details, type=BYTE_ARRAY, convertedtype=UTF8"`
	GroupName      string   `json:"group_name,omitempty" parquet:"name=group_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Labels         []string `json:"labels,omitempty" parquet:"name=labels, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Name           string   `json:"name,omitempty" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Owner          string   `json:"owner,omitempty" parquet:"name=owner, type=BYTE_ARRAY, convertedtype=UTF8"`
	Region         string   `json:"region,omitempty" parquet:"name=region, type=BYTE_ARRAY, convertedtype=UTF8"`
	Type           string   `json:"type,omitempty" parquet:"name=type, type=BYTE_ARRAY, convertedtype=UTF8"`
	UniqueID       string   `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type VulnerabilityDetails struct { //see https://schema.ocsf.io/objects/vulnerability
	CVSSScores             CVSS     `json:"cvss,omitempty" parquet:"name=cvss"`
	Description            string   `json:"desc,omitempty" parquet:"name=desc, type=BYTE_ARRAY, convertedtype=UTF8"`
	KnowledgebaseArticles  []string `json:"kb_articles,omitempty" parquet:"name=kb_articles, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	References             []string `json:"references,omitempty" parquet:"name=references, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	RelatedPackages        []string `json:"packages,omitempty" parquet:"name=packages, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	RelatedVulnerabilities []string `json:"related_vulnerabilities,omitempty" parquet:"name=related_vulnerabilities, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Severity               string   `json:"severity,omitempty" parquet:"name=severity, type=BYTE_ARRAY, convertedtype=UTF8"`
	Title                  string   `json:"title,omitempty" parquet:"name=title, type=BYTE_ARRAY, convertedtype=UTF8"`
	UniqueID               string   `json:"uid" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	VendorName             string   `json:"vendor_name,omitempty" parquet:"name=vendor_name, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type RelatedFindings struct { //see https://schema.ocsf.io/objects/related_findings
	ProductIdentifier string `json:"product_uid,omitempty" parquet:"name=product_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	UniqueID          string `json:"uid" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type Remediation struct { //see https://schema.ocsf.io/objects/remediation
	Description           string   `json:"desc,omitempty" parquet:"name=desc, type=BYTE_ARRAY, convertedtype=UTF8"`
	KnowledgebaseArticles []string `json:"kb_articles,omitempty" parquet:"name=kb_articles, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
}

type Product struct { //see https://schema.ocsf.io/objects/product
	Feature        Feature `json:"feature,omitempty" parquet:"name=feature"`
	Language       string  `json:"language,omitempty" parquet:"name=language, type=BYTE_ARRAY, convertedtype=UTF8"`
	ProductID      string  `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	ProductName    string  `json:"name" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	ProductPath    string  `json:"path,omitempty" parquet:"name=path, type=BYTE_ARRAY, convertedtype=UTF8"`
	ProductVersion string  `json:"version,omitempty" parquet:"name=version, type=BYTE_ARRAY, convertedtype=UTF8"`
	VendorName     string  `json:"vendor_name,omitempty" parquet:"name=vendor_name, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type File struct { //see https://schema.ocsf.io/objects/file
	AccessedTime       time.Time        `json:"accessed_time,omitempty" parquet:"name=accessed_time, type=TIMESTAMP_MILLIS"`
	Accessor           string           `json:"accessor,omitempty" parquet:"name=accessor, type=BYTE_ARRAY, convertedtype=UTF8"`
	Attributes         int32            `json:"attributes,omitempty" parquet:"name=attributes, type=INT32"`
	CompanyName        string           `json:"company_name,omitempty" parquet:"name=company_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Confidentiality    string           `json:"confidentiality,omitempty" parquet:"name=confidentiality, type=BYTE_ARRAY, convertedtype=UTF8"`
	ConfidentialityID  int32            `json:"confidentiality_id,omitempty" parquet:"name=confidentiality_id, type=INT32"`
	CreatedTime        time.Time        `json:"created_time,omitempty" parquet:"name=created_time, type=TIMESTAMP_MILLIS"`
	Creator            string           `json:"creator,omitempty" parquet:"name=creator, type=BYTE_ARRAY, convertedtype=UTF8"`
	Description        string           `json:"desc,omitempty" parquet:"name=desc, type=BYTE_ARRAY, convertedtype=UTF8"`
	DigitalSignature   DigitalSignature `json:"signature,omitempty" parquet:"name=signature"`
	ExtendedAttributes string           `json:"xattributes,omitempty" parquet:"name=xattributes, type=BYTE_ARRAY, convertedtype=UTF8"`
	Fingerprints       []Fingerprint    `json:"fingerprints,omitempty" parquet:"name=fingerprints type=LIST"`
	MIMEType           string           `json:"mime_type,omitempty" parquet:"name=mime_type, type=BYTE_ARRAY, convertedtype=UTF8"`
	ModifiedTime       time.Time        `json:"modified_time,omitempty" parquet:"name=modified_time, type=TIMESTAMP_MILLIS"`
	Modifier           string           `json:"modifier,omitempty" parquet:"name=modifier, type=BYTE_ARRAY, convertedtype=UTF8"`
	Name               string           `json:"name" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Owner              string           `json:"owner,omitempty" parquet:"name=owner, type=BYTE_ARRAY, convertedtype=UTF8"`
	ParentFolder       string           `json:"parent_folder,omitempty" parquet:"name=parent_folder, type=BYTE_ARRAY, convertedtype=UTF8"`
	Path               string           `json:"path,omitempty" parquet:"name=path, type=BYTE_ARRAY, convertedtype=UTF8"`
	Product            *Product         `json:"product,omitempty" parquet:"name=product, type=INT64"`
	SecurityDescriptor string           `json:"security_descriptor,omitempty" parquet:"name=security_descriptor, type=BYTE_ARRAY, convertedtype=UTF8"`
	Size               int32            `json:"size,omitempty" parquet:"name=size, type=INT32"`
	System             bool             `json:"is_system,omitempty" parquet:"name=is_system, type=BOOLEAN"`
	Type               string           `json:"type" parquet:"name=type, type=BYTE_ARRAY, convertedtype=UTF8"`
	TypeID             int32            `json:"type_id" parquet:"name=type_id, type=INT32"`
	UniqueID           string           `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	Version            string           `json:"version,omitempty" parquet:"name=version, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type User struct { //see https://schema.ocsf.io/objects/user
	AccountType      string  `json:"account_type,omitempty" parquet:"name=account_type, type=BYTE_ARRAY, convertedtype=UTF8"`
	AccountTypeID    int32   `json:"account_type_id,omitempty" parquet:"name=account_type_id, type=INT32"`
	AccountUID       string  `json:"account_uid,omitempty" parquet:"name=account_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	Domain           string  `json:"domain,omitempty" parquet:"name=domain, type=BYTE_ARRAY, convertedtype=UTF8"`
	EmailAddress     string  `json:"email_addr,omitempty" parquet:"name=email_addr, type=BYTE_ARRAY, convertedtype=UTF8"`
	Groups           []Group `json:"groups,omitempty" parquet:"name=groups type=LIST"`
	Name             string  `json:"name,omitempty" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	OrgID            string  `json:"org_uid,omitempty" parquet:"name=org_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	SessionUID       string  `json:"session_uid,omitempty" parquet:"name=session_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	SessionUUID      string  `json:"session_uuid,omitempty" parquet:"name=session_uuid, type=BYTE_ARRAY, convertedtype=UTF8"`
	Type             string  `json:"type,omitempty" parquet:"name=type, type=BYTE_ARRAY, convertedtype=UTF8"`
	TypeID           int32   `json:"type_id,omitempty" parquet:"name=type_id, type=INT32"`
	UniqueUserID     string  `json:"uuid,omitempty" parquet:"name=uuid, type=BYTE_ARRAY, convertedtype=UTF8"`
	UserCredentialID string  `json:"credential_uid,omitempty" parquet:"name=credential_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	UserID           string  `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type CVSS struct { //see https://schema.ocsf.io/objects/cvss
	AccessComplexity           int32   `json:"access_complexity_id,omitempty" parquet:"name=access_complexity_id, type=INT32"`
	AccessVector               int32   `json:"access_vector_id,omitempty" parquet:"name=access_vector_id, type=INT32"`
	AttackComplexity           int32   `json:"attack_complexity_id,omitempty" parquet:"name=attack_complexity_id, type=INT32"`
	AttackVector               int32   `json:"attack_vector_id,omitempty" parquet:"name=attack_vector_id, type=INT32"`
	Authentication             int32   `json:"authentication_id,omitempty" parquet:"name=authentication_id, type=INT32"`
	Availability               int32   `json:"availability_id,omitempty" parquet:"name=availability_id, type=INT32"`
	AvailabilityImpact         int32   `json:"availability_impact_id,omitempty" parquet:"name=availability_impact_id, type=INT32"`
	AvailabilityRequirement    int32   `json:"availability_requirement_id,omitempty" parquet:"name=availability_requirement_id, type=INT32"`
	CVSSDepth                  int32   `json:"depth_id,omitempty" parquet:"name=depth_id, type=INT32"`
	CollateralDamagePotential  int32   `json:"collateral_damage_potential_id,omitempty" parquet:"name=collateral_damage_potential_id, type=INT32"`
	Confidentiality            int32   `json:"confidentiality_id,omitempty" parquet:"name=confidentiality_id, type=INT32"`
	ConfidentialityImpact      int32   `json:"confidentiality_impact_id,omitempty" parquet:"name=confidentiality_impact_id, type=INT32"`
	ConfidentialityRequirement int32   `json:"confidentiality_requirement_id,omitempty" parquet:"name=confidentiality_requirement_id, type=INT32"`
	ExploitCodeMaturity        int32   `json:"exploit_code_maturity_id,omitempty" parquet:"name=exploit_code_maturity_id, type=INT32"`
	Exploitability             int32   `json:"exploitability_id,omitempty" parquet:"name=exploitability_id, type=INT32"`
	Integrity                  int32   `json:"integrity_id,omitempty" parquet:"name=integrity_id, type=INT32"`
	IntegrityImpact            int32   `json:"integrity_impact_id,omitempty" parquet:"name=integrity_impact_id, type=INT32"`
	IntegrityRequirement       int32   `json:"integrity_requirement_id,omitempty" parquet:"name=integrity_requirement_id, type=INT32"`
	ModifiedAttackComplexity   int32   `json:"modified_attack_complexity_id,omitempty" parquet:"name=modified_attack_complexity_id, type=INT32"`
	ModifiedAttackVector       int32   `json:"modified_attack_vector_id,omitempty" parquet:"name=modified_attack_vector_id, type=INT32"`
	ModifiedAvailability       int32   `json:"modified_availability_id,omitempty" parquet:"name=modified_availability_id, type=INT32"`
	ModifiedConfidentiality    int32   `json:"modified_confidentiality_id,omitempty" parquet:"name=modified_confidentiality_id, type=INT32"`
	ModifiedIntegrity          int32   `json:"modified_integrity_id,omitempty" parquet:"name=modified_integrity_id, type=INT32"`
	ModifiedPrivilegesRequired int32   `json:"modified_privileges_required_id,omitempty" parquet:"name=modified_privileges_required_id, type=INT32"`
	ModifiedScope              int32   `json:"modified_scope_id,omitempty" parquet:"name=modified_scope_id, type=INT32"`
	ModifiedUserInteraction    int32   `json:"modified_user_interaction_id,omitempty" parquet:"name=modified_user_interaction_id, type=INT32"`
	PrivilegesRequired         int32   `json:"privileges_required_id,omitempty" parquet:"name=privileges_required_id, type=INT32"`
	QualitativeSeverityRating  int32   `json:"severity_id,omitempty" parquet:"name=severity_id, type=INT32"`
	RemediationLevel           int32   `json:"remediation_level_id,omitempty" parquet:"name=remediation_level_id, type=INT32"`
	ReportConfidence           int32   `json:"report_confidence_id,omitempty" parquet:"name=report_confidence_id, type=INT32"`
	ReputationScore            float32 `json:"raw_score,omitempty" parquet:"name=raw_score, type=FLOAT"`
	Scope                      int32   `json:"scope_id,omitempty" parquet:"name=scope_id, type=INT32"`
	TargetDistribution         int32   `json:"target_distribution_id,omitempty" parquet:"name=target_distribution_id, type=INT32"`
	UserInteraction            int32   `json:"user_interaction_id,omitempty" parquet:"name=user_interaction_id, type=INT32"`
	VectorString               int32   `json:"vector_string,omitempty" parquet:"name=vector_string, type=INT32"`
	Version                    int32   `json:"version,omitempty" parquet:"name=version, type=INT32"`
}

type Feature struct { //see https://schema.ocsf.io/objects/feature
	FeatureID      string `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	FeatureName    string `json:"name,omitempty" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	FeatureVersion string `json:"version,omitempty" parquet:"name=version, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type DigitalSignature struct { //see https://schema.ocsf.io/objects/digital_signature
	CompanyName  string        `json:"company_name" parquet:"name=company_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	CreatedTime  time.Time     `json:"created_time,omitempty" parquet:"name=created_time, type=TIMESTAMP_MILLIS"`
	DeveloperUID string        `json:"developer_uid,omitempty" parquet:"name=developer_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	Fingerprints []Fingerprint `json:"fingerprints,omitempty" parquet:"name=fingerprints type=LIST"`
	IssuerName   string        `json:"issuer_name,omitempty" parquet:"name=issuer_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	SerialNumber string        `json:"serial_number,omitempty" parquet:"name=serial_number, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type Fingerprint struct { //see https://schema.ocsf.io/objects/fingerprint
	Algorithm   string `json:"algorithm" parquet:"name=algorithm, type=BYTE_ARRAY, convertedtype=UTF8"`
	AlgorithmID string `json:"algorithm_id" parquet:"name=algorithm_id, type=BYTE_ARRAY, convertedtype=UTF8"`
	Value       string `json:"value" parquet:"name=value, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type Group struct { //see https://schema.ocsf.io/objects/fingerprint
	AccountType string   `json:"type,omitempty" parquet:"name=type, type=BYTE_ARRAY, convertedtype=UTF8"`
	Description string   `json:"desc,omitempty" parquet:"name=desc, type=BYTE_ARRAY, convertedtype=UTF8"`
	Name        string   `json:"name" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Privileges  []string `json:"privileges,omitempty" parquet:"name=privileges, type=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	UniqueID    string   `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type SeverityID int

const (
	SeverityIDOther         = -1
	SeverityIDUnknown       = 0
	SeverityIDInformational = 1
	SeverityIDLow           = 2
	SeverityIDMedium        = 3
	SeverityIDHigh          = 4
	SeverityIDCritical      = 5
	SeverityIDFatal         = 6
)

type ActivityID int

const (
	ActivityIDOther    = -1
	ActivityIDUnknown  = 0
	ActivityIDGenerate = 1
	ActivityIDUpdate   = 2
)

type CategoryUID int

const (
	CategoryUIDOther                  = -1
	CategoryUIDUnknown                = 0
	CategoryUIDSystemActivity         = 1
	CategoryUIDFindings               = 2
	CategoryUIDAuditActivity          = 3
	CategoryUIDNetworkActivity        = 4
	CategoryUIDCloudActivity          = 5
	CategoryUIDVirtualizationActivity = 6
	CategoryUIDDatabaseActivity       = 7
	CategoryUIDApplicationActivity    = 8
	CategoryUIDConfigurationInventory = 9
)

type ClassUID int

const (
	ClassUIDFileSystemActivity     = 1000
	ClassUIDKernelActivity         = 1003
	ClassUIDMemoryActivity         = 1004
	ClassUIDModuleActivity         = 1005
	ClassUIDProcessActivity        = 1007
	ClassUIDRegistryKeyActivity    = 1008
	ClassUIDRegistryValueActivity  = 1009
	ClassUIDResourceActivity       = 1010
	ClassUIDScheduledJobActivity   = 1011
	ClassUIDKernelExtension        = 1013
	ClassUIDSecurityFinding        = 2001
	ClassUIDAccountChange          = 3001
	ClassUIDAuthentication         = 3002
	ClassUIDAuthorization          = 3003
	ClassUIDEntityManagementAudit  = 3004
	ClassUIDNetworkActivity        = 4001
	ClassUIDHttpActivity           = 4002
	ClassUIDDnsActivity            = 4003
	ClassUIDDhcpActivity           = 4004
	ClassUIDRdpActivity            = 4005
	ClassUIDSmbActivity            = 4006
	ClassUIDSshActivity            = 4007
	ClassUIDFtpActivity            = 4008
	ClassUIDRfbActivity            = 4009
	ClassUIDSmtpActivity           = 4010
	ClassUIDCloudApi               = 5001
	ClassUIDCloudStorage           = 5002
	ClassUIDContainerLifecycle     = 6001
	ClassUIDVirtualMachineActivity = 6002
	ClassUIDDatabaseLifecycle      = 7000
	ClassUIDAccessActivity         = 8001
	ClassUIDInventoryInfo          = 9001
	ClassUIDConfigState            = 9002
)

type StateID int

const (
	StateIDOther      = -1
	StateIDUnknown    = 0
	StateIDNew        = 1
	StateIDInProgress = 2
	StateIDSuppressed = 3
	StateIDResolved   = 4
)

type TypeUID int

const (
	TypeUIDOther    = -1
	TypeUIDUnknown  = 200100
	TypeUIDGenerate = 200101
	TypeUIDUpdate   = 200102
)
