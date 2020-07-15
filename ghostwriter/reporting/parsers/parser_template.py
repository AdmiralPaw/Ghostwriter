# This is template for another parsers
# Use class below to create new parser
# To make it work, find the 'reporting:import_from' method
# and add your new parser according to the instructions
import logging.config

logger = logging.getLogger(__name__)
LOGGING_CONFIG = None
logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'console': {
            # Format: timestamp + name + 12 spaces + info level + 8 spaces + message
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'console',
        },
    },
    'loggers': {
        '': {
            'level': 'INFO',
            'handlers': ['console'],
        },
    },
})

GHOSTWRITTER_FIELDS = ['parserID',
                       'title',
                       'description',
                       'affected_entities',
                       'severity',
                       'severity_weight',
                       'impact',
                       'mitigation',
                       'replication_steps',
                       'host_detection_techniques',
                       'network_detection_techniques',
                       'references',
                       'finding_type',
                       'finding_guidance']

class Parser:
    def begin_parse(self, file):
        res = self.parse_file(file)
        # res must be 'list'
        if not isinstance(res, list):
            logger.error('Parser output must be \'list()\'')
        # Primitive check all needed fields in output list
        try:
            for field in GHOSTWRITTER_FIELDS:
                tmp = res[0][field]
        except Exception as error:
            logger.error('Parser output doesn\'t have all the necessary fields– %s', error)
            return None
        # Validate findings
        unique_id = list()
        finally_res = list()
        for finding in res:
            if finding['parserID'] in unique_id or finding['parserID'] == '0':
                continue
            elif finding['title'] == '':
                continue
            else:
                unique_id.append(finding['parserID'])
                finally_res.append(finding)

        return finally_res

    def parse_file(self, context):
        pass
