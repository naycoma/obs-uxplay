#pragma once
#include "audio-decoder.hpp"
#include "h264-decoder.hpp"
#include <memory>
#include <stream.h>
#include <vector>

class AirPlay {
public:
  AirPlay(struct obs_data *data, struct obs_source *obsSource);
  ~AirPlay();
  auto getWidth() const -> int;
  auto getHeight() const -> int;
  auto name() const -> const char *;

private:
  auto render(const audio_decode_struct *data) -> void;
  auto render(const h264_decode_struct *data) -> void;
  auto start_raop_server(std::vector<char> hw_addr,
                         std::string name,
                         unsigned short tcp[3],
                         unsigned short udp[3],
                         bool debug_log) -> int;

  auto stop_raop_server() -> void;
  auto start_dnssd(std::vector<char> hw_addr, std::string name) -> int;
  auto stop_dnssd() -> void;
  auto register_dnssd() -> int;
  auto unregister_dnssd() -> void;
  // Server callbacks
  static auto register_client(void *cls,
                              const char *device_id,
                              const char *client_pk,
                              const char *client_name) -> void;
  static auto check_register(void *cls, const char *client_pk) -> bool;
  static auto audio_flush(void *cls) -> void;
  static auto audio_get_format(void *cls,
                               unsigned char *ct,
                               unsigned short *spf,
                               bool *usingScreen,
                               bool *isMedia,
                               uint64_t *audioFormat) -> void;
  static auto audio_process(void *cls, struct raop_ntp_s *ntp, audio_decode_struct *data) -> void;
  static auto audio_set_metadata(void *cls, const void *buffer, int buflen) -> void;
  static auto audio_set_volume(void *cls, float volume) -> void;
  static auto conn_destroy(void *cls) -> void;
  static auto conn_init(void *cls) -> void;
  static auto conn_reset(void *cls, int timeouts, bool reset_video) -> void;
  static auto conn_teardown(void *cls, bool *teardown_96, bool *teardown_110) -> void;
  static auto log_callback(void *cls, int level, const char *msg) -> void;
  static auto video_flush(void *cls) -> void;
  static auto video_process(void *cls, struct raop_ntp_s *ntp, h264_decode_struct *data) -> void;
  static auto video_report_size(void *cls,
                                float *width_source,
                                float *height_source,
                                float *width,
                                float *height) -> void;

  struct obs_data *obsData;
  struct obs_source *obsSource;
  std::unique_ptr<struct obs_source_frame> obsVFrame;
  H264Decoder vDecoder;
  std::unique_ptr<struct obs_source_audio> obsAFrame;
  AudioDecoder aDecoder;
  bool connections_stopped = false;
  unsigned int counter = 0;
  unsigned char compression_type = 0;
  struct raop_s *raop = NULL;
  struct dnssd_s *dnssd = NULL;
  int open_connections = 0;
  int width = 320;
  int height = 320;
  
  std::string keyfile = "";
  std::string mac_address = "";
  unsigned short raop_port = 0;
  unsigned short airplay_port = 0;
  std::vector <std::string> registered_keys;
  std::string server_name = "";
};
