require 'fluent/plugin/output'

module Fluent
  module Plugin
    class OutSyslogRFC5424 < Output

      def initialize()
        @host = 'custom-14.ngc-2.srvs.ahdev.co'
        @port = '1999'
        @transport = 'tls'
        @insecure = true
        @trusted_ca_path = '/Users/sagar.wankhade/Documents/syslog_certs/remote_syslog_bundle.pem'
        @private_key_path = '/Users/sagar.wankhade/Documents/syslog_certs/remote_syslog_client_key.pem'
        @private_key_passphrase = nil
        @allow_self_signed_cert = true
        @version = 'TLSv1_2'
        puts 'hello'
      end

      Fluent::Plugin.register_output('syslog_rfc5424', self)

      helpers :socket, :formatter
      DEFAULT_FORMATTER = "syslog_rfc5424"

      config_section :format do
        config_set_default :@type, DEFAULT_FORMATTER
      end

      def configure(config)
        super
        @sockets = {}
        @formatter = formatter_create
      end

      def multi_workers_ready?
        true
      end

      def write(chunk)
        socket = find_or_create_socket(@transport.to_sym, @host, @port)
        puts "entering TLS handshake"
        socket.write 'Hello from sagar'
        tag = chunk.metadata.tag
        chunk.each do |time, record|
          begin
            socket.write_nonblock @formatter.format(tag, time, record)
            IO.select(nil, [socket], nil, 1) || raise(StandardError.new "ReconnectError")
          rescue => e
            @sockets.delete(socket_key(@transport.to_sym, @host, @port))
            socket.close
            raise
          end
        end
      end

      def close
        super
        @sockets.each_value { |s| s.close }
        @sockets = {}
      end

      private

      def find_or_create_socket(transport, host, port)
        socket = find_socket(transport, host, port)
        return socket if socket
        @sockets[socket_key(transport, host, port)] = socket_create(transport.to_sym, host, port, socket_options)
      end

      def socket_options
        if @transport == 'udp'
          { connect: true }
        elsif @transport == 'tls'
          # TODO: make timeo
          # uts configurable
          {
            insecure: @insecure,
            verify_fqdn: !@insecure,
            cert_paths: @trusted_ca_path,
            private_key_path: @private_key_path,
            private_key_passphrase: @private_key_passphrase,
            allow_self_signed_cert: @allow_self_signed_cert,
            fqdn: @fqdn,
            version: @version.to_sym,
          } #, connect_timeout: 1, send_timeout: 1, recv_timeout: 1, linger_timeout: 1 }
        else
          {}
        end
      end

      def socket_key(transport, host, port)
        "#{host}:#{port}:#{transport}"
      end

      def find_socket(transport, host, port)
        @sockets[socket_key(transport, host, port)]
      end
    end
  end
end
