#define _GNU_SOURCE
#include "../backend/udp_attribution.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static char directory[] = "/tmp/exl-udp-attribution-XXXXXX";
static char udp_path[128], udp6_path[128];
static const char header[] =
    " sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n";
static unsigned char local4[4], remote4[4], local6[16], remote6[16];
static unsigned int checks;

static void cleanup(void)
{
    unlink(udp_path); unlink(udp6_path); rmdir(directory);
}

static FILE *table(const char *path)
{
    FILE *file = fopen(path, "w");
    assert(file && fputs(header, file) >= 0);
    return file;
}

static void empty_tables(void)
{
    assert(fclose(table(udp_path)) == 0);
    assert(fclose(table(udp6_path)) == 0);
}

static void row(FILE *file, const char *local, const char *remote,
                 const char *state, unsigned long inode)
{
    assert(fprintf(file, "0: %s %s %s 00000000:00000000 00:00000000 00000000 1000 0 %lu 2 0000000000000000 0\n",
                   local, remote, state, inode) > 0);
}

static void expect_tuple(enum udp_attribution_result expected, unsigned long wanted,
                          int family, const unsigned char *local, unsigned short local_port,
                          const unsigned char *remote, unsigned short remote_port)
{
    unsigned long inode = 0xbad;
    enum udp_attribution_result result = udp_attribution_lookup_files(udp_path, udp6_path,
        family, local, local_port, remote, remote_port, &inode);
    if (result != expected || inode != wanted)
        fprintf(stderr, "check %u: expected result=%d inode=%lu got result=%d inode=%lu\n",
                checks, expected, wanted, result, inode);
    assert(result == expected && inode == wanted);
    ++checks;
}

static void expect(enum udp_attribution_result expected, unsigned long wanted)
{
    expect_tuple(expected, wanted, AF_INET, local4, 40000, remote4, 443);
}

static void connected_and_unconnected(void)
{
    empty_tables(); expect(UDP_ATTR_NONE, 0);
    FILE *file = table(udp_path);
    row(file, "0302017F:9C40", "0A6433C6:01BB", "01", 11);
    row(file, "0302017F:9C40", "096433C6:01BC", "01", 22);
    row(file, "0402017F:9C40", "096433C6:01BB", "01", 33);
    row(file, "0302017F:9C41", "096433C6:01BB", "01", 44);
    row(file, "0302017F:9C40", "096433C6:01BB", "01", 0);
    assert(fclose(file) == 0); expect(UDP_ATTR_NONE, 0);
    file = fopen(udp_path, "a"); assert(file);
    row(file, "0302017F:9C40", "096433C6:01BB", "01", 55);
    row(file, "0302017F:9C40", "096433C6:01BB", "01", 55);
    assert(fclose(file) == 0); expect(UDP_ATTR_FOUND, 55);
    file = table(udp_path);
    row(file, "0302017F:9C40", "00000000:0000", "07", 66);
    assert(fclose(file) == 0); expect(UDP_ATTR_FOUND, 66);
    file = table(udp_path);
    row(file, "00000000:9C40", "00000000:0000", "07", 77);
    assert(fclose(file) == 0); expect(UDP_ATTR_FOUND, 77);
    unsigned char other[4]; assert(inet_pton(AF_INET, "203.0.113.9", other) == 1);
    expect_tuple(UDP_ATTR_FOUND, 77, AF_INET, local4, 40000, other, 61234);
    file = table(udp_path);
    row(file, "00000000:9C40", "096433C6:01BB", "01", 88);
    assert(fclose(file) == 0); expect(UDP_ATTR_FOUND, 88);
}

static void ambiguity(void)
{
    const char *locals[] = {"0302017F:9C40", "00000000:9C40"};
    for (unsigned int wildcard = 0; wildcard < 2; ++wildcard) {
        for (unsigned int reverse = 0; reverse < 2; ++reverse) {
            empty_tables(); FILE *file = table(udp_path);
            row(file, locals[reverse ? wildcard : 0], "00000000:0000", "07", reverse ? 101 : 202);
            row(file, locals[reverse ? 0 : wildcard], "00000000:0000", "07", reverse ? 202 : 101);
            assert(fclose(file) == 0); expect(UDP_ATTR_AMBIGUOUS, 0);
        }
    }
    empty_tables(); FILE *file = table(udp_path);
    row(file, "0302017F:9C40", "096433C6:01BB", "01", 101);
    row(file, "0302017F:9C40", "00000000:0000", "07", 202);
    assert(fclose(file) == 0); expect(UDP_ATTR_AMBIGUOUS, 0);
    file = table(udp_path);
    row(file, "0302017F:9C40", "00000000:0000", "07", 101);
    row(file, "00000000:9C40", "00000000:0000", "07", 101);
    assert(fclose(file) == 0); expect(UDP_ATTR_FOUND, 101);
}

static void ipv6_and_mapped(void)
{
    empty_tables(); FILE *file = table(udp6_path);
    row(file, "B80D012078563412F0DEBC9A78563412:9C40",
        "B80D012000CD00AB020100EF06050403:01BC", "01", 11);
    row(file, "B80D012078563412F0DEBC9A78563412:9C40",
        "B80D012000CD00AB020100EF06050403:01BB", "01", 22);
    assert(fclose(file) == 0);
    expect_tuple(UDP_ATTR_FOUND, 22, AF_INET6, local6, 40000, remote6, 443);
    file = table(udp6_path);
    row(file, "00000000000000000000000000000000:9C40",
        "00000000000000000000000000000000:0000", "07", 33);
    assert(fclose(file) == 0);
    expect_tuple(UDP_ATTR_FOUND, 33, AF_INET6, local6, 40000, remote6, 443);
    /* An IPv4 query cannot know whether an IPv6 ANY socket is V6ONLY. */
    expect(UDP_ATTR_AMBIGUOUS, 0);
    file = table(udp6_path);
    row(file, "0000000000000000FFFF00000302017F:9C40",
        "000000000000000000000000096433C6:01BB", "01", 44);
    row(file, "0000000000000000FFFF00000302017F:9C40",
        "0000000000000000FFFF00000A6433C6:01BB", "01", 55);
    assert(fclose(file) == 0); expect(UDP_ATTR_NONE, 0);
    file = fopen(udp6_path, "a"); assert(file);
    row(file, "0000000000000000FFFF00000302017F:9C40",
        "0000000000000000FFFF0000096433C6:01BB", "01", 66);
    assert(fclose(file) == 0); expect(UDP_ATTR_FOUND, 66);
    file = table(udp_path);
    row(file, "0302017F:9C40", "096433C6:01BB", "01", 77);
    assert(fclose(file) == 0); expect(UDP_ATTR_AMBIGUOUS, 0);
    file = table(udp_path);
    row(file, "0302017F:9C40", "096433C6:01BB", "01", 66);
    assert(fclose(file) == 0); expect(UDP_ATTR_FOUND, 66);
    file = table(udp6_path);
    row(file, "0000000000000000FFFF00000302017F:9C40",
        "00000000000000000000000000000000:0000", "07", 88);
    assert(fclose(file) == 0);
    assert(fclose(table(udp_path)) == 0); expect(UDP_ATTR_FOUND, 88);
    unsigned char scoped[16]; assert(inet_pton(AF_INET6, "fe80::1", scoped) == 1);
    expect_tuple(UDP_ATTR_INVALID, 0, AF_INET6, scoped, 40000, remote6, 443);
    expect_tuple(UDP_ATTR_INVALID, 0, AF_INET6, local6, 40000, scoped, 443);
}

static void malformed_and_limits(void)
{
    static const char *const parts[] = {"0:", "0302017F:9C40", "096433C6:01BB", "01",
        "00000000:00000000", "00:00000000", "00000000", "1000", "0", "12345"};
    static const struct { unsigned int part; const char *value; } bad[] = {
        {0,"-1:"},{0,"+1:"},{0,"4294967296:"},{0,"1:x"},
        {1,"302017F:9C40"},{1,"0302017G:9C40"},{1,"0302017F:19C40"},
        {2,"096433CG:01BB"},{2,"096433C6:01B"},{2,"096433C6:+1BB"},
        {3,"00"},{3,"0A"},{3,"FF"},{3,"001"},
        {4,"0000000:00000000"},{4,"00000000:0000000G"},
        {5,"0:00000000"},{5,"00:000000000"},{6,"0000000"},
        {7,"+1000"},{7,"4294967296"},{8,"-1"},{9,"12345junk"},
        {9,"+12345"},{9,"18446744073709551616"}
    };
    for (size_t n = 0; n < sizeof(bad)/sizeof(bad[0]); ++n) {
        empty_tables(); FILE *file = table(udp_path);
        row(file, parts[1], parts[2], "01", 12345);
        for (unsigned int field = 0; field < 10; ++field)
            assert(fprintf(file, "%s%c", field == bad[n].part ? bad[n].value : parts[field], field == 9 ? '\n' : ' ') > 0);
        assert(fclose(file) == 0); expect(UDP_ATTR_INVALID, 0);
    }
    empty_tables(); FILE *file = table(udp_path);
    row(file, parts[1], parts[2], "07", 12345); /* contradictory unconnected peer */
    assert(fclose(file) == 0); expect(UDP_ATTR_INVALID, 0);
    file = fopen(udp_path, "w"); assert(file);
    assert(fputs("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n", file) >= 0);
    assert(fclose(file) == 0); expect(UDP_ATTR_INVALID, 0);
    file = table(udp_path);
    assert(fputs("0: 0302017F:9C40 096433C6:01BB 01\n", file) >= 0);
    assert(fclose(file) == 0); expect(UDP_ATTR_INVALID, 0);
    file = table(udp_path);
    assert(fputs("0: 0302017F:9C40 096433C6:01BB 01 00000000:00000000 00:00000000 00000000 1000 0 12345", file) >= 0);
    assert(fclose(file) == 0); expect(UDP_ATTR_INVALID, 0);
    file = table(udp_path);
    for (unsigned int n=0; n<2048; ++n) assert(fputc('0',file)!=EOF);
    assert(fputc('\n',file)!=EOF && fclose(file)==0); expect(UDP_ATTR_INVALID,0);
    empty_tables();
    assert(unlink(udp6_path)==0); expect(UDP_ATTR_INVALID,0);
    assert(mkfifo(udp6_path,0600)==0); expect(UDP_ATTR_INVALID,0);
    assert(unlink(udp6_path)==0);
    assert(symlink(udp_path,udp6_path)==0); expect(UDP_ATTR_INVALID,0);
    assert(unlink(udp6_path)==0);
    assert(fclose(table(udp6_path))==0);
    file = table(udp_path);
    for (unsigned int n=0;n<65537;++n) row(file,"00000000:9C41","00000000:0000","07",1);
    assert(fclose(file)==0); expect(UDP_ATTR_INVALID,0);
}

static void arguments_and_boundaries(void)
{
    empty_tables(); FILE *file=table(udp_path);
    row(file,"0302017f:0000","096433c6:ffff","01",ULONG_MAX);
    assert(fclose(file)==0);
    expect_tuple(UDP_ATTR_FOUND,ULONG_MAX,AF_INET,local4,0,remote4,65535);
    unsigned long inode=55;
    assert(udp_attribution_lookup_files(NULL,udp6_path,AF_INET,local4,1,remote4,1,&inode)==UDP_ATTR_INVALID && !inode);
    inode=55; assert(udp_attribution_lookup_files(udp_path,NULL,AF_INET,local4,1,remote4,1,&inode)==UDP_ATTR_INVALID && !inode);
    inode=55; assert(udp_attribution_lookup_files(udp_path,udp6_path,AF_UNIX,local4,1,remote4,1,&inode)==UDP_ATTR_INVALID && !inode);
    inode=55; assert(udp_attribution_lookup_files(udp_path,udp6_path,AF_INET,NULL,1,remote4,1,&inode)==UDP_ATTR_INVALID && !inode);
    inode=55; assert(udp_attribution_lookup_files(udp_path,udp6_path,AF_INET,local4,1,NULL,1,&inode)==UDP_ATTR_INVALID && !inode);
    assert(udp_attribution_lookup_files(udp_path,udp6_path,AF_INET,local4,1,remote4,1,NULL)==UDP_ATTR_INVALID);
}

static unsigned long socket_inode(int fd)
{
    struct stat info; assert(fstat(fd,&info)==0 && info.st_ino>0);
    return (unsigned long)info.st_ino;
}

static void live_expect(enum udp_attribution_result expected,unsigned long wanted,int family,
                          const unsigned char *local,unsigned short lport,
                          const unsigned char *remote,unsigned short rport)
{
    unsigned long inode=55;
    enum udp_attribution_result result=udp_attribution_lookup(family,local,lport,remote,rport,&inode);
    if (result!=expected || inode!=wanted)
        fprintf(stderr,"live expected=%d/%lu got=%d/%lu family=%d\n",expected,wanted,result,inode,family);
    assert(result==expected && inode==wanted); ++checks;
}

static int udp_socket(int family,int wildcard,unsigned short port)
{
    int fd=socket(family,SOCK_DGRAM,0); assert(fd>=0);
    int one=1; assert(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))==0);
    if(family==AF_INET){
        struct sockaddr_in local={0}; local.sin_family=AF_INET; local.sin_port=htons(port);
        local.sin_addr.s_addr=htonl(wildcard?INADDR_ANY:INADDR_LOOPBACK);
        assert(bind(fd,(struct sockaddr*)&local,sizeof(local))==0);
    }else{
        struct sockaddr_in6 local={0}; local.sin6_family=AF_INET6; local.sin6_port=htons(port);
        local.sin6_addr=wildcard?in6addr_any:in6addr_loopback;
        assert(bind(fd,(struct sockaddr*)&local,sizeof(local))==0);
    }
    return fd;
}

static unsigned short bound_port(int fd,int family)
{
    struct sockaddr_storage address; socklen_t length=sizeof(address);
    assert(getsockname(fd,(struct sockaddr*)&address,&length)==0);
    return family==AF_INET?ntohs(((struct sockaddr_in*)&address)->sin_port):ntohs(((struct sockaddr_in6*)&address)->sin6_port);
}

static void live_ipv4(void)
{
    unsigned char ip[4]; assert(inet_pton(AF_INET,"127.0.0.1",ip)==1);
    int a=udp_socket(AF_INET,1,0); unsigned short port=bound_port(a,AF_INET);
    live_expect(UDP_ATTR_FOUND,socket_inode(a),AF_INET,ip,port,ip,44001);
    live_expect(UDP_ATTR_FOUND,socket_inode(a),AF_INET,ip,port,ip,44002);
    int b=udp_socket(AF_INET,0,port);
    live_expect(UDP_ATTR_AMBIGUOUS,0,AF_INET,ip,port,ip,44001);
    assert(close(a)==0 && close(b)==0);
    live_expect(UDP_ATTR_NONE,0,AF_INET,ip,port,ip,44001);
    a=udp_socket(AF_INET,0,0); port=bound_port(a,AF_INET);
    b=udp_socket(AF_INET,0,port);
    struct sockaddr_in peer={0}; peer.sin_family=AF_INET; peer.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    peer.sin_port=htons(44001); assert(connect(a,(struct sockaddr*)&peer,sizeof(peer))==0);
    peer.sin_port=htons(44002); assert(connect(b,(struct sockaddr*)&peer,sizeof(peer))==0);
    live_expect(UDP_ATTR_FOUND,socket_inode(a),AF_INET,ip,port,ip,44001);
    live_expect(UDP_ATTR_FOUND,socket_inode(b),AF_INET,ip,port,ip,44002);
    live_expect(UDP_ATTR_NONE,0,AF_INET,ip,port,ip,44003);
    assert(close(a)==0 && close(b)==0);
}

static void live_ipv6(void)
{
    unsigned char ip[16]; assert(inet_pton(AF_INET6,"::1",ip)==1);
    int a=udp_socket(AF_INET6,1,0); unsigned short port=bound_port(a,AF_INET6);
    live_expect(UDP_ATTR_FOUND,socket_inode(a),AF_INET6,ip,port,ip,44001);
    int b=udp_socket(AF_INET6,0,port);
    live_expect(UDP_ATTR_AMBIGUOUS,0,AF_INET6,ip,port,ip,44001);
    assert(close(a)==0 && close(b)==0);
    a=udp_socket(AF_INET6,0,0);port=bound_port(a,AF_INET6);
    b=udp_socket(AF_INET6,0,port);
    struct sockaddr_in6 peer={0};peer.sin6_family=AF_INET6;peer.sin6_addr=in6addr_loopback;
    peer.sin6_port=htons(44001);assert(connect(a,(struct sockaddr*)&peer,sizeof(peer))==0);
    peer.sin6_port=htons(44002);assert(connect(b,(struct sockaddr*)&peer,sizeof(peer))==0);
    live_expect(UDP_ATTR_FOUND,socket_inode(a),AF_INET6,ip,port,ip,44001);
    live_expect(UDP_ATTR_FOUND,socket_inode(b),AF_INET6,ip,port,ip,44002);
    assert(close(a)==0 && close(b)==0);
    /* A v6-only ANY bind is never evidence for an IPv4 socket. */
    a=socket(AF_INET6,SOCK_DGRAM,0);assert(a>=0);int one=1;
    assert(setsockopt(a,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one))==0);
    struct sockaddr_in6 local={0};local.sin6_family=AF_INET6;local.sin6_addr=in6addr_any;
    assert(bind(a,(struct sockaddr*)&local,sizeof(local))==0);port=bound_port(a,AF_INET6);
    unsigned char ip4[4];assert(inet_pton(AF_INET,"127.0.0.1",ip4)==1);
    live_expect(UDP_ATTR_AMBIGUOUS,0,AF_INET,ip4,port,ip4,44001);
    assert(close(a)==0);
}

static void live_reuseport_and_mapped(void)
{
    unsigned char ip[4]; assert(inet_pton(AF_INET,"127.0.0.1",ip)==1);
    int sockets[2], one=1; unsigned short port=0;
    for(unsigned int n=0;n<2;++n){
        sockets[n]=socket(AF_INET,SOCK_DGRAM,0);assert(sockets[n]>=0);
        assert(setsockopt(sockets[n],SOL_SOCKET,SO_REUSEPORT,&one,sizeof(one))==0);
        struct sockaddr_in local={0};local.sin_family=AF_INET;
        local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);local.sin_port=htons(port);
        assert(bind(sockets[n],(struct sockaddr*)&local,sizeof(local))==0);
        if(!n)port=bound_port(sockets[n],AF_INET);
    }
    live_expect(UDP_ATTR_AMBIGUOUS,0,AF_INET,ip,port,ip,44001);
    assert(close(sockets[0])==0 && close(sockets[1])==0);

    int fd=socket(AF_INET6,SOCK_DGRAM,0);assert(fd>=0);
    int zero=0;assert(setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&zero,sizeof(zero))==0);
    struct sockaddr_in6 local={0},peer={0};local.sin6_family=AF_INET6;
    assert(inet_pton(AF_INET6,"::ffff:127.0.0.1",&local.sin6_addr)==1);
    assert(bind(fd,(struct sockaddr*)&local,sizeof(local))==0);
    peer=local;peer.sin6_port=htons(44001);
    assert(connect(fd,(struct sockaddr*)&peer,sizeof(peer))==0);
    port=bound_port(fd,AF_INET6);
    live_expect(UDP_ATTR_FOUND,socket_inode(fd),AF_INET,ip,port,ip,44001);
    live_expect(UDP_ATTR_FOUND,socket_inode(fd),AF_INET6,
        (const unsigned char*)&local.sin6_addr,port,(const unsigned char*)&peer.sin6_addr,44001);
    assert(close(fd)==0);
}

int main(void)
{
    assert(mkdtemp(directory));
    assert(snprintf(udp_path,sizeof(udp_path),"%s/udp",directory)>0);
    assert(snprintf(udp6_path,sizeof(udp6_path),"%s/udp6",directory)>0);
    assert(atexit(cleanup)==0);
    assert(inet_pton(AF_INET,"127.1.2.3",local4)==1);
    assert(inet_pton(AF_INET,"198.51.100.9",remote4)==1);
    assert(inet_pton(AF_INET6,"2001:db8:1234:5678:9abc:def0:1234:5678",local6)==1);
    assert(inet_pton(AF_INET6,"2001:db8:ab00:cd00:ef00:102:304:506",remote6)==1);
    connected_and_unconnected();ambiguity();ipv6_and_mapped();
    malformed_and_limits();arguments_and_boundaries();live_ipv4();live_ipv6();
    live_reuseport_and_mapped();
    printf("PASS: UDP attribution fixtures/live sockets (%u cases), connected peers, wildcards, bounds and ambiguity\n",checks);
    return 0;
}
