require 'socket'
require 'ipaddr'
require 'openssl'
require 'fluent/tls'

class VerifyCert
  def initialize()
    @name = 'World'
    @sockets = {}
    @host = 'custom-14.ngc-2.srvs.ahdev.co'
    @port = 2000
    @transport = 'tls'
    @insecure = false
    @trusted_ca_path = '/Users/sagar.wankhade/Documents/syslog_certs/remote_syslog_bundle.pem'
    @private_key_path = '/Users/sagar.wankhade/Documents/syslog_certs/remote_syslog_client_key.pem'
    @private_key_passphrase = nil
    @allow_self_signed_cert = true
    @version = 'TLSv1_2'
  end
  def verifyAndSendMsg
    socket_create(@transport.to_sym, @host, @port, socket_options)
  end

  def socket_create_tls(
    host, port,
    version: Fluent::TLS::DEFAULT_VERSION, min_version: nil, max_version: nil, ciphers: Fluent::TLS::CIPHERS_DEFAULT, insecure: false, verify_fqdn: true, fqdn: nil,
    enable_system_cert_store: true, allow_self_signed_cert: false, cert_paths: nil,
    cert_path: nil, private_key_path: nil, private_key_passphrase: nil,
    cert_thumbprint: nil, cert_logical_store_name: nil, cert_use_enterprise_store: true,
    **kwargs, &block)

    host_is_ipaddress = IPAddr.new(host) rescue false
    fqdn ||= host unless host_is_ipaddress

    context = OpenSSL::SSL::SSLContext.new

    if insecure
      puts "setting TLS verify_mode NONE"
      context.verify_mode = OpenSSL::SSL::VERIFY_NONE
    else
      cert_store = OpenSSL::X509::Store.new
      if allow_self_signed_cert && OpenSSL::X509.const_defined?('V_FLAG_CHECK_SS_SIGNATURE')
        cert_store.flags = OpenSSL::X509::V_FLAG_CHECK_SS_SIGNATURE
      end
      begin
        if enable_system_cert_store
          puts "loading system default certificate store"
          cert_store.set_default_paths
        end
      rescue OpenSSL::X509::StoreError
        log.warn "failed to load system default certificate store", error: e
      end
      if cert_paths
        if cert_paths.respond_to?(:each)
          cert_paths.each do |cert_path|
            puts "adding CA cert", path: cert_path
            cert_store.add_file(cert_path)
          end
        else
          cert_path = cert_paths
          puts "adding CA cert", path: cert_path
          cert_store.add_file(cert_path)
        end
      end

      puts "setting TLS context", mode: "peer", ciphers: ciphers
      context.set_params({})
      context.ciphers = ciphers
      context.verify_mode = OpenSSL::SSL::VERIFY_PEER
      context.cert_store = cert_store
      context.verify_hostname = verify_fqdn && fqdn
      context.key = OpenSSL::PKey::read(File.read(private_key_path), private_key_passphrase) if private_key_path

      if cert_path
        certs = socket_certificates_from_file(cert_path)
        context.cert = certs.shift
        unless certs.empty?
          context.extra_chain_cert = certs
        end
      end
    end
    Fluent::TLS.set_version_to_context(context, version, min_version, max_version)

    tcpsock = socket_create_tcp(host, port, **kwargs)
    sock = WrappedSocket::TLS.new(tcpsock, context)
    sock.sync_close = true
    sock.hostname = fqdn if verify_fqdn && fqdn && sock.respond_to?(:hostname=)

    puts "entering TLS handshake"
    sock.connect
    sock.write 'Hello from Sagar'
    sock.close

    begin
      if verify_fqdn
        puts "checking peer's certificate", subject: sock.peer_cert.subject
        sock.post_connection_check(fqdn)
        verify = sock.verify_result
        if verify != OpenSSL::X509::V_OK
          err_name = Socket.tls_verify_result_name(verify)
          log.warn "BUG: failed to verify certification while connecting (but not raised, why?)", host: host, fqdn: fqdn, error: err_name
          raise RuntimeError, "BUG: failed to verify certification and to handle it correctly while connecting host #{host} as #{fqdn}"
        end
      end
    rescue OpenSSL::SSL::SSLError => e
      log.warn "failed to verify certification while connecting tls session", host: host, fqdn: fqdn, error: e
      raise
    end

    if block
      begin
        block.call(sock)
      ensure
        sock.close rescue nil
      end
    else
      sock
    end
  end

  def socket_options
    {
      insecure: @insecure,
      verify_fqdn: !@insecure,
      cert_paths: @trusted_ca_path,
      private_key_path: @private_key_path,
      private_key_passphrase: @private_key_passphrase,
      allow_self_signed_cert: @allow_self_signed_cert,
      fqdn: @fqdn,
      version: @version.to_sym,
    }
  end
  def socket_create(proto, host, port, **kwargs, &block)
    case proto
    when :tcp
      socket_create_tcp(host, port, **kwargs, &block)
    when :udp
      socket_create_udp(host, port, **kwargs, &block)
    when :tls
      socket_create_tls(host, port, **kwargs, &block)
    when :unix
      raise "not implemented yet"
    else
      raise ArgumentError, "invalid protocol: #{proto}"
    end
  end
  def socket_create_tcp(host, port, resolve_name: false, connect_timeout: nil, **kwargs, &block)
    sock = if connect_timeout
             s = ::Socket.tcp(host, port, connect_timeout: connect_timeout)
             s.autoclose = false # avoid GC triggered close
             WrappedSocket::TCP.for_fd(s.fileno)
           else
             WrappedSocket::TCP.new(host, port)
           end
    socket_option_set(sock, resolve_name: resolve_name, **kwargs)
    if block
      begin
        block.call(sock)
      ensure
        sock.close_write rescue nil
        sock.close rescue nil
      end
    else
      sock
    end
  end
  module WrappedSocket
    class TCP < ::TCPSocket
      def remote_addr; peeraddr[3]; end
      def remote_host; peeraddr[2]; end
      def remote_port; peeraddr[1]; end
    end
    class UDP < ::UDPSocket
      def remote_addr; peeraddr[3]; end
      def remote_host; peeraddr[2]; end
      def remote_port; peeraddr[1]; end
    end
    class TLS < OpenSSL::SSL::SSLSocket
      def remote_addr; peeraddr[3]; end
      def remote_host; peeraddr[2]; end
      def remote_port; peeraddr[1]; end
    end
  end
  def socket_option_set(sock, resolve_name: nil, nonblock: false, linger_timeout: nil, recv_timeout: nil, send_timeout: nil, receive_buffer_size: nil, send_keepalive_packet: nil)
    unless resolve_name.nil?
      sock.do_not_reverse_lookup = !resolve_name
    end
    if nonblock
      sock.fcntl(Fcntl::F_SETFL, Fcntl::O_NONBLOCK)
    end
    if linger_timeout
      optval = [1, linger_timeout.to_i].pack(FORMAT_STRUCT_LINGER)
      socket_option_set_one(sock, :SO_LINGER, optval)
    end
    if recv_timeout
      optval = [recv_timeout.to_i, 0].pack(FORMAT_STRUCT_TIMEVAL)
      socket_option_set_one(sock, :SO_RCVTIMEO, optval)
    end
    if send_timeout
      optval = [send_timeout.to_i, 0].pack(FORMAT_STRUCT_TIMEVAL)
      socket_option_set_one(sock, :SO_SNDTIMEO, optval)
    end
    if receive_buffer_size
      socket_option_set_one(sock, :SO_RCVBUF, receive_buffer_size.to_i)
    end
    if send_keepalive_packet
      socket_option_set_one(sock, :SO_KEEPALIVE, true)
    end
    sock
  end
  def socket_certificates_from_file(path)
    data = File.read(path)
    pattern = Regexp.compile('-+BEGIN CERTIFICATE-+\r?\n(?:[^-]*\r?\n)+-+END CERTIFICATE-+\r?\n?', Regexp::MULTILINE)
    list = []
    data.scan(pattern) { |match| list << OpenSSL::X509::Certificate.new(match) }
    if list.length == 0
      raise Fluent::ConfigError, "cert_path does not contain a valid certificate"
    end
    list
  end
end

hello = VerifyCert.new()
hello.verifyAndSendMsg
