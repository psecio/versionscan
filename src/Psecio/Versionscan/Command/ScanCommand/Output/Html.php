<?php
namespace Psecio\Versionscan\Command\ScanCommand\Output;

use Psecio\Versionscan\Command\Output;
use Symfony\Component\Console\Command\Command;

class Html extends Output
{
    public function render($results, Command $command)
    {
        $output = $this->getOption('outputPath');

        if (!is_writable($output)) {
            throw new \RuntimeException(sprintf('Ouput path "%s" is not writable', $output));
        }

        $values = array(
            'date' => date('m.d.Y H:i:s'),
            'results' => ''
        );

        foreach ($results as $result) {
            $values['results'] .=  sprintf(
                '<div class="result %1$s">
                    <table cellpadding="2" cellspacing="0" border="0" class="result">
                        <tr>
                            <td class="key"><a href="http://www.cvedetails.com/cve/%2$s/">%2$s</a></td>
                            <td class="risk">%3$s</td>
                            <td>%4$s</td>
                        </tr>
                    </table>
                </div>
                <br/>',
                $result['status'],
                $result['cve-id'],
                $result['risk'],
                $result['summary']
            );
        }

        $template = file_get_contents(__DIR__ . '/../Templates/html.html');
        foreach ($values as $key => $value) {
            $template = str_replace('{{' . $key . '}}', $value, $template);
        }

        $output = sprintf('%s/versionscan-output-%s.html', rtrim($output, '/'), date('Ymd'));
        file_put_contents($output, $template);
    }
}
