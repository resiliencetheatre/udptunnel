#include <utun/socket.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void put(const char *path, const void *data, size_t n)
{
    FILE *f = fopen(path, "wb"); assert(f);
    assert(fwrite(data, 1, n, f) == n); assert(fclose(f) == 0);
}
static long counter(const char *path)
{
    long v; FILE *f = fopen(path,"rb"); assert(f);
    assert(fread(&v,sizeof(v),1,f)==1); fclose(f); return v;
}
int main(void)
{
    char dir[] = "/tmp/udptunnel-tests-XXXXXX";
    assert(mkdtemp(dir));
    char tx[256],rx[256],tc[256],rc[256];
    snprintf(tx,sizeof(tx),"%s/tx",dir); snprintf(rx,sizeof(rx),"%s/rx",dir);
    snprintf(tc,sizeof(tc),"%s/tc",dir); snprintf(rc,sizeof(rc),"%s/rc",dir);
    unsigned char key[10000]; for(size_t i=0;i<sizeof(key);i++) key[i]=(i*37+13)%256;
    long zero=0; put(tx,key,sizeof(key)); put(rx,key,sizeof(key));
    put(tc,&zero,sizeof(zero)); put(rc,&zero,sizeof(zero));
    assert(transport_config_valid(tx,tc));
    assert(transport_files_distinct(tx,rx,tc,rc));
    assert(!transport_files_distinct(tx,tx,tc,rc));
    assert(!transport_config_valid("/nonexistent/udptunnel-key",tc));
    assert(!transport_config_valid(tx,"/nonexistent/udptunnel-counter"));
    char plain[1500], out[1500]; memset(plain,0x42,sizeof(plain)); plain[0]=1; plain[1]=0;
    unsigned char wire[1600], bad[1600];
    int lengths[]={2,100,50,1500};
    long used=0;
    for(size_t k=0;k<sizeof(lengths)/sizeof(*lengths);k++) {
        int len=lengths[k];
        int n=encryptpacket(plain,len,wire,sizeof(wire),tx,tc);
        assert(n==10+len+32);
        /* The header starts directly with the offset, followed by length. */
        unsigned long long encoded_offset=0;
        for (int j=0;j<8;j++) encoded_offset=(encoded_offset<<8)|wire[j];
        assert(encoded_offset==(unsigned long long)used);
        assert((((unsigned int)wire[8]<<8)|wire[9])==(unsigned int)len);
        /* A legacy signature-prefixed packet must not be accepted. */
        memcpy(bad,"UTN2",4); memcpy(bad+4,wire,n);
        assert(!decryptpacket(out,sizeof(out),bad,n+4,rx,rc));
        assert(counter(tc)==used+len+32);
        /* Every truncation and every single-byte tampering must be rejected. */
        for(int j=0;j<n;j++) assert(!decryptpacket(out,sizeof(out),wire,j,rx,rc));
        for(int j=0;j<n;j++) {
            memcpy(bad,wire,n); bad[j]^=1;
            assert(!decryptpacket(out,sizeof(out),bad,n,rx,rc));
        }
        assert(counter(rc)==used);
        assert(!decryptpacket(out,len-1,wire,n,rx,rc));
        assert(decryptpacket(out,sizeof(out),wire,n,rx,rc)==len);
        assert(!memcmp(out,plain,len));
        used+=len+32; assert(counter(rc)==used);
        assert(!decryptpacket(out,sizeof(out),wire,n,rx,rc)); /* replay */
    }
    /* A lost packet may leave a gap; later authenticated traffic still works. */
    assert(encryptpacket(plain,100,wire,sizeof(wire),tx,tc)>0);
    int n=encryptpacket(plain,50,wire,sizeof(wire),tx,tc);
    assert(decryptpacket(out,sizeof(out),wire,n,rx,rc)==50);
    assert(counter(tc)==counter(rc));
    /* Sender filtering happens before decryption or key consumption. */
    int receiver=socket_create(0), sender=socket_create(0);
    struct sockaddr_in dest, source, from;
    socklen_t addrlen=sizeof(dest);
    assert(getsockname(receiver,(struct sockaddr *)&dest,&addrlen)==0);
    addrlen=sizeof(source);
    assert(getsockname(sender,(struct sockaddr *)&source,&addrlen)==0);
    dest.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    source.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    n=encryptpacket(plain,100,wire,sizeof(wire),tx,tc); assert(n>0);
    long before=counter(rc);
    struct sockaddr_in wrong=source; wrong.sin_port=0;
    assert(sendto(sender,wire,n,0,(struct sockaddr *)&dest,sizeof(dest))==n);
    assert(!socket_get_packet(receiver,&from,&addrlen,out,sizeof(out),rx,rc,&wrong));
    assert(counter(rc)==before);
    assert(sendto(sender,wire,n,0,(struct sockaddr *)&dest,sizeof(dest))==n);
    assert(socket_get_packet(receiver,&from,&addrlen,out,sizeof(out),rx,rc,&source)==100);
    assert(!memcmp(out,plain,100));
    close(sender); close(receiver);
    /* Insufficient key material must neither emit plaintext nor advance state. */
    put(tx,key,4); put(tc,&zero,sizeof(zero));
    assert(!encryptpacket(plain,8,wire,sizeof(wire),tx,tc)); assert(counter(tc)==0);
    assert(!encryptpacket(plain,1501,wire,sizeof(wire),tx,tc));
    put(tc,"x",1); assert(!transport_config_valid(tx,tc));
    assert(!encryptpacket(plain,8,wire,sizeof(wire),tx,tc));
    unlink(tx); unlink(rx); unlink(tc); unlink(rc); rmdir(dir);
    puts("transport tests passed");
}
