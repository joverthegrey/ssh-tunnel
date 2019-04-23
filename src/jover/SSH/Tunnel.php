<?php

declare(strict_types=1);

namespace jover\SSH;

use Exception as SSHException;

class Tunnel
{
    /**
     * keepalive setting in seconds
     */
    private const SSH_SERVER_ALIVE_INTERVAL = 15;

    /**
     * process of the established ssh tunnel
     * @var null
     */
    private $process = null;

    /**
     *
     * pipe description to the std buffers
     * @var array
     */
    private $descriptorspec = [
        0 => ["pipe", "r"],  // stdin is a pipe that the child will read from
        1 => ["pipe", "w"],  // stdout is a pipe that the child will write to
        2 => ["pipe", "w"]   // stderr is a pipe to write to
    ];

    /**
     * pipes to the process
     * @var array
     */
    private $pipes = [];

    /**
     * Tunnel constructor.
     *
     * @param array $config
     * @throws SSHException
     */
    public function __construct(array $config = [])
    {
        if (!empty($config)) {
            $this->open($config);
        }
    }

    /**
     * generate a public and private key
     *
     * @return array
     */
    public static function generateKeyPair(): array
    {
        exec("ssh-keygen -b 2048 -t rsa -f ./ssh.key -N '' -q");

        $res = [
            'private' => file_get_contents('./ssh.key'),
            'public' => file_get_contents('./ssh.key.pub'),
        ];

        @unlink('./ssh.key');
        @unlink('./ssh.key.pub');

        return $res;
    }

    /**
     * Open SSH tunnel defined by config
     *
     * @param array $config
     *
     * Configuration fields:
     *
     * - user: (string) SSH proxy username. Required.
     * - sshHost: (string) SSH proxy hostname. Required.
     * - sshPort: (string) SSH protocol port. Optional, default 22.
     * - localPort: (string) local port. Optional, default 33006.
     * - remoteHost: (string) destination machine hostname. Required.
     * - remotePort: (string) destination machine port. Required.
     * - privateKey: (string) SSH private key. Required.
     * - compression: (bool) whether to use compression. Optional, default false.
     *
     *
     * @return true
     * @throws SSHException
     */
    public function open(array $config): bool
    {
        $config = $this->validateConfig($config);
        $keyFile = $this->writeKeyToFile($config['privateKey']);

        if (is_resource($this->process) && $this->status['running'] == true) {
            throw new SSHException('Tunnel already established');
        }

        $this->process = proc_open($this->createSshCommand($config, $keyFile), $this->descriptorspec, $this->pipes);

        // wait a bit
        sleep(1);

        // remove the tempfile with the key
        @unlink($keyFile);

        if (!is_resource($this->process) || $this->status['running'] == false) {

            $out=null;
            $err=null;

            if (is_resource($this->process)) {
                $out = trim(stream_get_contents($this->pipes[1]));
                $err = trim(stream_get_contents($this->pipes[2]));
            }

            foreach ($this->pipes as $pipe) {
                fclose($pipe);
            }
            proc_close($this->process);

            throw new SSHException(
                'Couldn\'t open SSH tunnel' .
                (!empty($out) ? ': ' . $out : '') .
                (!empty($err) ? ' Error: ' . $err : '')
            );
        }

        return true;
    }

    /**
     * return the status of the process
     *
     * @return array
     */
    private function status(): array
    {
        $status = [];
        if (is_resource($this->process))
        {
            $status = proc_get_status($this->process);

            // augment $status, cause proc_get_status thinks the process is stopped ??
            if (posix_kill($status['pid'], 0)) {
                $status['running'] = true;
                $status['exitcode'] = 0;
            }
        }
        return $status;
    }

    /**
     * close the tunnel
     */
    public function close()
    {
        $status = $this->status;

        if (!empty($status)) {
            $pid = $status['pid'];

            // cleanup the php end of the process
            foreach ($this->pipes as $pipe) {
                fclose($pipe);
            }

            // terminate tunnel
            posix_kill($pid, SIGTERM);

            // defensive programming (just in case)
            posix_kill($pid, SIGKILL);
        }
        $this->process = null;
    }

    /**
     * create the ssh command
     *
     * @param array $config
     * @return string
     * @throws SSHException
     */
    private function createSshCommand(array $config, $keyFile): string
    {

        $cmd = [
            'exec ssh',
            '-p',
            $config['sshPort'],
            sprintf('%s@%s', $config['user'], $config['sshHost']),
            '-L',
            sprintf('%s:%s:%s', $config['localPort'], $config['remoteHost'], $config['remotePort']),
            '-i',
            $keyFile,
            '-Nn',
            '-o',
            sprintf('ServerAliveInterval=%d', self::SSH_SERVER_ALIVE_INTERVAL),
            '-o',
            'StrictHostKeyChecking=no',
            '-o',
            'BatchMode=yes',
            '-o',
            'PreferredAuthentications=publickey',
        ];

        if (isset($config['compression']) && $config['compression'] === true) {
            $cmd[] = '-C';
        }

        return implode(' ',$cmd);
    }

    /**
     * check the config
     *
     * @param array $config
     * @return array
     * @throws SSHException
     */
    private function validateConfig(array $config): array
    {
        $defaultValues = [
            'sshPort' => 22,
            'localPort' => 33006,
            'compression' => false,
        ];

        $configWithDefaults = array_merge($defaultValues, $config);

        $missingParams = array_diff(
            ['user', 'sshHost', 'sshPort', 'localPort', 'remoteHost', 'remotePort', 'privateKey'],
            array_keys($configWithDefaults)
        );

        if (!empty($missingParams)) {
            throw new SSHException(sprintf("Missing parameters '%s'", implode(',', $missingParams)));
        }

        return $configWithDefaults;
    }

    /**
     * write the private key to a temp file
     *
     * @param string $key
     * @return string
     * @throws SSHException
     */
    private function writeKeyToFile(string $key): string
    {
        if (empty($key)) {
            throw new SSHException("Key must not be empty");
        }
        $fileName = (string) tempnam('/tmp/', 'ssh-key-');

        file_put_contents($fileName, $key);
        chmod($fileName, 0600);

        return (string) realpath($fileName);
    }

    /**
     * magic getter
     *
     * @param $name
     * @return array|bool|null
     */
    public function __get($name)
    {
        // just implement the status
        switch($name) {
            case 'status':
                return $this->status();
                break;
            default:
                return null;
                break;
        }
    }

    /**
     * nice cleanup on destruction
     */
    public function __destruct()
    {
        $this->close();
    }
}
