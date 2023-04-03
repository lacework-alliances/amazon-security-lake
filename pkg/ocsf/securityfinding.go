package ocsf

type SecurityFinding struct { //see https://schema.ocsf.io/classes/security_finding
	ActivityID     int32          `json:"activity_id" parquet:"name=activity_id, type=INT32, convertedtype=INT_32"` //required
	Category       string         `json:"category_name" parquet:"name=category_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	CategoryUID    int32          `json:"category_uid" parquet:"name=category_uid, type=INT32, convertedtype=INT_32"` //required
	Class          string         `json:"class_name" parquet:"name=class_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	ClassUID       int32          `json:"class_uid" parquet:"name=class_uid, type=INT32, convertedtype=INT_32"` //required
	Data           string         `json:"data,omitempty" parquet:"name=data, type=BYTE_ARRAY, convertedtype=UTF8"`
	EventTime      int64          `json:"time" parquet:"name=time, type=INT64, convertedtype=TIMESTAMP_MILLIS"`          //required
	Finding        FindingDetails `json:"finding" parquet:"name=finding"`                                                //required
	Message        string         `json:"message,omitempty" parquet:"name=message, type=BYTE_ARRAY, convertedtype=UTF8"` //recommended
	Metadata       Metadata       `json:"metadata" parquet:"name=metadata"`                                              //required
	ResourcesArray []Resource     `json:"resources,omitempty" parquet:"name=resources type=LIST"`                        //recommended
	SeverityID     int32          `json:"severity_id" parquet:"name=severity_id, type=INT32, convertedtype=INT_32"`      //required
	StateID        int32          `json:"state_id" parquet:"name=state_id, type=INT32, convertedtype=INT_32"`            //required
	TypeID         int32          `json:"type_uid" parquet:"name=type_uid, type=INT32, convertedtype=INT_32"`            //required             //required
	TypeName       string         `json:"type_name,omitempty" parquet:"name=type_name, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type FindingDetails struct { //see https://schema.ocsf.io/objects/finding
	CreatedTime    int64    `json:"created_time,omitempty" parquet:"name=created_time, type=INT64, convertedtype=TIMESTAMP_MILLIS"`
	Description    string   `json:"desc,omitempty" parquet:"name=desc, type=BYTE_ARRAY, convertedtype=UTF8"`
	SourceURL      string   `json:"src_url,omitempty" parquet:"name=src_url, type=BYTE_ARRAY, convertedtype=UTF8"`
	SupportingData []string `json:"supporting_data,omitempty" parquet:"name=support_data, type=MAP, convertedtype=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Title          string   `json:"title" parquet:"name=title, type=BYTE_ARRAY, convertedtype=UTF8"` //required
	UniqueID       string   `json:"uid" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`     //required
}

type Metadata struct { //see https://schema.ocsf.io/objects/metadata
	EventUID     string  `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	OriginalTime string   `json:"original_time,omitempty" parquet:"name=original_time, type=BYTE_ARRAY, convertedtype=UTF8"`
	Product      Product `json:"product" parquet:"name=product"`
	Version      string  `json:"version" parquet:"name=version, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type Resource struct { //see https://schema.ocsf.io/objects/resource
	AccountUID     int32    `json:"account_uid,omitempty" parquet:"name=account_uid, type=INT32, convertedtype=INT_32"`
	CloudPartition string   `json:"cloud_partition,omitempty" parquet:"name=cloud_partition, type=BYTE_ARRAY, convertedtype=UTF8"`
	Criticality    string   `json:"criticality,omitempty" parquet:"name=criticality, type=BYTE_ARRAY, convertedtype=UTF8"`
	Details        string   `json:"details,omitempty" parquet:"name=details, type=BYTE_ARRAY, convertedtype=UTF8"`
	GroupName      string   `json:"group_name,omitempty" parquet:"name=group_name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Labels         []string `json:"labels,omitempty" parquet:"name=labels, type=MAP, convertedtype=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
	Name           string   `json:"name,omitempty" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	Owner          string   `json:"owner,omitempty" parquet:"name=owner, type=BYTE_ARRAY, convertedtype=UTF8"`
	Region         string   `json:"region,omitempty" parquet:"name=region, type=BYTE_ARRAY, convertedtype=UTF8"`
	Type           string   `json:"type,omitempty" parquet:"name=type, type=BYTE_ARRAY, convertedtype=UTF8"`
	UniqueID       string   `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type RelatedFindings struct { //see https://schema.ocsf.io/objects/related_findings
	ProductIdentifier string `json:"product_uid,omitempty" parquet:"name=product_uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	UniqueID          string `json:"uid" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
}

type Remediation struct { //see https://schema.ocsf.io/objects/remediation
	Description           string   `json:"desc,omitempty" parquet:"name=desc, type=BYTE_ARRAY, convertedtype=UTF8"`
	KnowledgebaseArticles []string `json:"kb_articles,omitempty" parquet:"name=kb_articles, type=MAP, convertedtype=LIST, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
}

type Product struct { //see https://schema.ocsf.io/objects/product
	Language       string `json:"language,omitempty" parquet:"name=language, type=BYTE_ARRAY, convertedtype=UTF8"`
	ProductID      string `json:"uid,omitempty" parquet:"name=uid, type=BYTE_ARRAY, convertedtype=UTF8"`
	ProductName    string `json:"name" parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8"`
	ProductVersion string `json:"version,omitempty" parquet:"name=version, type=BYTE_ARRAY, convertedtype=UTF8"`
	VendorName     string `json:"vendor_name,omitempty" parquet:"name=vendor_name, type=BYTE_ARRAY, convertedtype=UTF8"`
}
