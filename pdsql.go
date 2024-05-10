// Package pdsql implements a plugin that query powerdns database to resolve the coredns query
package pdsql

import (
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/drahoslavzan/coredns-pdsql/pdnsmodel"
	"github.com/drahoslavzan/srvutils/env"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/jinzhu/gorm"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

const Name = "pdsql"

type PowerDNSGenericSQLBackend struct {
	*gorm.DB
	Debug bool
	Next  plugin.Handler

	ttl     uint32
	recA    net.IP
	recAAAA net.IP
	recSOA  dns.SOA
	recMX   string
	recNS   string
}

func NewPowerDNSGenericSQLBackend() *PowerDNSGenericSQLBackend {
	ret := &PowerDNSGenericSQLBackend{
		recA:    net.ParseIP(env.String("A")),
		recAAAA: net.ParseIP(env.String("AAAA")),
		recMX:   env.String("MX"),
		recNS:   env.String("NS"),
		ttl:     uint32(env.IntDef("TTL", 3600)),
	}

	if !ParseSOA(&ret.recSOA, env.String("SOA")) {
		panic("parsing SOA failed")
	}

	return ret
}

func (pdb PowerDNSGenericSQLBackend) Name() string { return Name }

func (pdb PowerDNSGenericSQLBackend) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	a := new(dns.Msg)
	a.SetReply(r)
	a.Compress = true
	a.Authoritative = true

	qname := strings.ToLower(state.QName())

	var domains []*pdnsmodel.Domain
	query := pdnsmodel.Domain{Name: qname}
	if query.Name != "." {
		// remove last dot
		query.Name = query.Name[:len(query.Name)-1]
	}

	if err := pdb.Where(query).Find(&domains).Limit(1).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			rr := pdb.recSOA
			rr.Hdr = dns.RR_Header{Name: qname, Rrtype: dns.TypeSOA, Class: state.QClass()}
			a.Extra = append(a.Extra, &rr)
		} else {
			return dns.RcodeServerFailure, err
		}
	} else if len(domains) > 0 {
		stype := strings.ToUpper(state.Type())
		typ := dns.StringToType[stype]
		hdr := dns.RR_Header{Name: qname, Rrtype: typ, Class: state.QClass(), Ttl: pdb.ttl}
		if !strings.HasSuffix(hdr.Name, ".") {
			hdr.Name += "."
		}
		rr := dns.TypeToRR[typ]()

		switch rr := rr.(type) {
		// name records, such as NS, MX, etc. have to be fully qualified domain names, ending with the dot.

		case *dns.SOA:
			*rr = pdb.recSOA
			rr.Hdr = hdr
		case *dns.NS:
			rr.Hdr = hdr
			rr.Ns = pdb.recNS
		case *dns.A:
			rr.Hdr = hdr
			rr.A = pdb.recA
		case *dns.AAAA:
			rr.Hdr = hdr
			rr.AAAA = pdb.recAAAA
		case *dns.MX:
			rr.Hdr = hdr
			rr.Mx = pdb.recMX
			rr.Preference = 1
		default:
			// drop unsupported
			if pdb.Debug {
				log.Printf("unsupported RR type: %s\n", stype)
			}
		}

		if rr == nil {
			if pdb.Debug {
				log.Printf("invalid RR type: %s\n", stype)
			}
		} else {
			a.Answer = append(a.Answer, rr)
		}
	}

	if len(a.Answer) == 0 {
		return plugin.NextOrFailure(pdb.Name(), pdb.Next, ctx, w, r)
	}

	return 0, w.WriteMsg(a)
}

func (pdb PowerDNSGenericSQLBackend) SearchWildcard(qname string, qtype uint16) (records []*pdnsmodel.Record, err error) {
	// find domain, then find matched sub domain
	name := qname
	qnameNoDot := qname[:len(qname)-1]
	typ := dns.TypeToString[qtype]
	name = qnameNoDot
NEXT_ZONE:
	if i := strings.IndexRune(name, '.'); i > 0 {
		name = name[i+1:]
	} else {
		return
	}
	var domain pdnsmodel.Domain

	if err := pdb.Limit(1).Find(&domain, "name = ?", name).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			goto NEXT_ZONE
		}
		return nil, err
	}

	if err := pdb.Find(&records, "dns_domain_id = ? AND (? = 'ANY' OR rec_type = ?) AND name LIKE '%*%'", domain.ID, typ, typ).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	// filter
	var matched []*pdnsmodel.Record
	for _, v := range records {
		if WildcardMatch(qnameNoDot, v.Name) {
			matched = append(matched, v)
		}
	}
	records = matched
	return
}

func ParseSOA(rr *dns.SOA, line string) bool {
	splites := strings.Split(line, " ")
	if len(splites) < 7 {
		return false
	}
	rr.Ns = splites[0]
	rr.Mbox = splites[1]
	if i, err := strconv.Atoi(splites[2]); err != nil {
		return false
	} else {
		rr.Serial = uint32(i)
	}
	if i, err := strconv.Atoi(splites[3]); err != nil {
		return false
	} else {
		rr.Refresh = uint32(i)
	}
	if i, err := strconv.Atoi(splites[4]); err != nil {
		return false
	} else {
		rr.Retry = uint32(i)
	}
	if i, err := strconv.Atoi(splites[5]); err != nil {
		return false
	} else {
		rr.Expire = uint32(i)
	}
	if i, err := strconv.Atoi(splites[6]); err != nil {
		return false
	} else {
		rr.Minttl = uint32(i)
	}
	return true
}

// Dummy wildcard match
func WildcardMatch(s1, s2 string) bool {
	if s1 == "." || s2 == "." {
		return true
	}

	l1 := dns.SplitDomainName(s1)
	l2 := dns.SplitDomainName(s2)

	if len(l1) != len(l2) {
		return false
	}

	for i := range l1 {
		if !equal(l1[i], l2[i]) {
			return false
		}
	}

	return true
}

func equal(a, b string) bool {
	if b == "*" || a == "*" {
		return true
	}
	// might be lifted into API function.
	la := len(a)
	lb := len(b)
	if la != lb {
		return false
	}

	for i := la - 1; i >= 0; i-- {
		ai := a[i]
		bi := b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai != bi {
			return false
		}
	}
	return true
}
