import scrapy
import pathlib
from datetime import datetime

class RouteviewsSpider(scrapy.Spider):
    name = 'bot_getbgp_rawdata'

    def __init__(self, *args, **kwargs):
        super(RouteviewsSpider, self).__init__(*args, **kwargs)

        #self.base_dir = '/root/mycontainer-bgp'
        self.base_dir = '/datadrive-slow/mycontainer-bgp'
        self.dir_path_file_pattern = "{base_dir}/{lbl_bgp_data_provider}/{lbl_collector}/{month_data}/"
        self.save_dir_path_file_pattern = "{base_dir}/{lbl_bgp_data_provider}/{lbl_collector}/{month_data}/{filename}"
        self.date_limit_max_downloads = None

    def start_requests(self):
        # Example of URL formats
        # url = 'http://archive.routeviews.org/bgpdata/2017.05/UPDATES/'
        # url = 'http://data.ris.ripe.net/rrc15/2017.05/'

        url = getattr(self, 'url', None)
        page = getattr(self, 'page', None)
        dir_to_save_files = getattr(self, 'bgpdirdata', None)

        if dir_to_save_files is not None:
            self.base_dir = dir_to_save_files

        # 2019.05
        # date_base = getattr(self, 'datebase', None)

        # get input param "datelimit" definied by user
        # e.g.: 20190615 --> stop downloads when reaches the defined date
        date_limit_downloads = getattr(self, 'datelimit', None)
        if date_limit_downloads is not None:
            self.date_limit_max_downloads = datetime.strptime(date_limit_downloads, '%Y%m%d')

        if url is not None:
            if page == 'routeviews':
                lbl_collector = url.split("/")[-5]
                month = url.split("/")[-3]

                # exception only for the "route-views2.oregon-ix.net"
                if lbl_collector == "archive.routeviews.org":
                    lbl_collector = "route-views2"

                dir_path_file = self.dir_path_file_pattern.format(base_dir=self.base_dir,
                                                                  lbl_bgp_data_provider="routeviews",
                                                                  lbl_collector=lbl_collector, month_data=month)
                pathlib.Path(dir_path_file).mkdir(parents=True, exist_ok=True)

                yield scrapy.Request(url=url, callback=self.parse_routeviews)

            elif page == 'ripe':
                lbl_collector = url.split("/")[-3]
                month = url.split("/")[-2]

                dir_path_file = self.dir_path_file_pattern.format(base_dir=self.base_dir,
                                                                  lbl_bgp_data_provider="ripe",
                                                                  lbl_collector=lbl_collector, month_data=month)
                pathlib.Path(dir_path_file).mkdir(parents=True, exist_ok=True)

                yield scrapy.Request(url=url, callback=self.parse_ripe)

    def parse_routeviews(self, response):
        #page = response.url.split("/")[-3]
        #filename = page + '/routeviews.txt'
        #f = open(filename, 'w')

        for line in response.xpath('//table/tr/td/a')[1:]:
            link = line.xpath('@href').extract_first()
            url = response.urljoin(link)

            if self.date_limit_max_downloads is not None:
                # extract date from file name at the current URL
                date_from_url = datetime.strptime(url.split('/')[-1].split('.')[1], '%Y%m%d')
                if date_from_url <= self.date_limit_max_downloads:
                    yield scrapy.Request(url=url, callback=self.parse_routeviews_file)
            else:
                yield scrapy.Request(url=url, callback=self.parse_routeviews_file)

            #f.write(url + '\n')
        #f.close()
        #self.log('Saved file %s' % filename)

    def parse_ripe(self, response):
        #page = response.url.split("/")[-2]
        #filename = page + '/ripe.txt'
        #f = open(filename, 'w')

        for line in response.xpath('//table/tr/td/a')[1:]:
            link = line.xpath('@href').extract_first()
            url = response.urljoin(link)

            if self.date_limit_max_downloads is not None:
                # extract date from file name at the current URL
                date_from_url = datetime.strptime(url.split('/')[-1].split('.')[1], '%Y%m%d')
                if date_from_url <= self.date_limit_max_downloads:
                    yield scrapy.Request(url=url, meta={'download_timeout': 600}, callback=self.parse_ripe_file)
            else:
                yield scrapy.Request(url=url, meta={'download_timeout': 600}, callback=self.parse_ripe_file)

            #f.write(url + '\n')
        #f.close()
        #self.log('Saved file %s' % filename)

    def parse_routeviews_file(self, response):

        lbl_collector = response.url.split("/")[-5]
        month = response.url.split("/")[-3]
        filename = response.url.split('/')[-1]

        # exception only for the "route-views2.oregon-ix.net"
        if lbl_collector == "archive.routeviews.org":
            lbl_collector = "route-views2"

        path_file = self.save_dir_path_file_pattern.format(base_dir=self.base_dir,
                                                           lbl_bgp_data_provider="routeviews",
                                                           lbl_collector=lbl_collector,
                                                           month_data=month, filename=filename)

        self.logger.info('Saving bz2 file %s', path_file)
        with open(path_file, 'wb') as f:
            f.write(response.body)

    def parse_ripe_file(self, response):

        lbl_collector = response.url.split("/")[-3]
        month = response.url.split("/")[-2]
        filename = response.url.split('/')[-1]

        path_file = self.save_dir_path_file_pattern.format(base_dir=self.base_dir,
                                                           lbl_bgp_data_provider="ripe",
                                                           lbl_collector=lbl_collector,
                                                           month_data=month, filename=filename)

        self.logger.info('Saving gz file %s', path_file)
        with open(path_file, 'wb') as f:
            f.write(response.body)
