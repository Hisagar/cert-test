





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
    log.trace "setting TLS verify_mode NONE"
    context.verify_mode = OpenSSL::SSL::VERIFY_NONE
  else
    cert_store = OpenSSL::X509::Store.new
    if allow_self_signed_cert && OpenSSL::X509.const_defined?('V_FLAG_CHECK_SS_SIGNATURE')
      cert_store.flags = OpenSSL::X509::V_FLAG_CHECK_SS_SIGNATURE
    end
    begin
      if enable_system_cert_store
        if Fluent.windows? && cert_logical_store_name
          log.trace "loading Windows system certificate store"
          loader = Certstore::OpenSSL::Loader.new(log, cert_store, cert_logical_store_name,
                                                  enterprise: cert_use_enterprise_store)
          loader.load_cert_store
          cert_store = loader.cert_store
          context.cert = loader.get_certificate(cert_thumbprint) if cert_thumbprint
        end
        log.trace "loading system default certificate store"
        cert_store.set_default_paths
      end
    rescue OpenSSL::X509::StoreError
      log.warn "failed to load system default certificate store", error: e
    end
    if cert_paths
      if cert_paths.respond_to?(:each)
        cert_paths.each do |cert_path|
          log.trace "adding CA cert", path: cert_path
          cert_store.add_file(cert_path)
        end
      else
        cert_path = cert_paths
        log.trace "adding CA cert", path: cert_path
        cert_store.add_file(cert_path)
      end
    end

    log.trace "setting TLS context", mode: "peer", ciphers: ciphers
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

  log.trace "entering TLS handshake"
  sock.connect

  begin
    if verify_fqdn
      log.trace "checking peer's certificate", subject: sock.peer_cert.subject
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