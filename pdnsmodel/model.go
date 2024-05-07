package pdnsmodel

type Domain struct {
	ID   uint64 `gorm:"column:dns_domain_id"`
	Name string `gorm:"column:name"`
}

type Record struct {
	ID       uint64 `gorm:"column:dns_record_id"`
	DomainID uint64 `gorm:"column:dns_domain_id"`
	Name     string `gorm:"column:name"`
	Type     string `gorm:"column:rec_type"`
	Content  string `gorm:"column:content"`
	Ttl      uint32 `gorm:"column:ttl"`
	Disabled bool   `gorm:"column:disabled"`
}

func (Domain) TableName() string {
	return "dns_domains"
}

func (Record) TableName() string {
	return "dns_records"
}
