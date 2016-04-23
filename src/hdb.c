#include <mruby.h>
#include <mruby/data.h>
#include <mruby/value.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <stdio.h>
#include <tcutil.h>
#include <tchdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct hdb_context {
	TCHDB*	hdb;
	struct mrb_data_type type;
} hdb_context;

static void hdb_free(mrb_state *mrb, void *p) {
  struct hdb_context *context = p;
  tchdbdel(context->hdb);
  mrb_free(mrb, p);
}

static mrb_value
hdb_initialize(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = mrb_malloc(mrb, sizeof(struct hdb_context));
  memset(context, 0, sizeof(*context));

  context->type.struct_name = "HDB";
  context->type.dfree = hdb_free;

  context->hdb = tchdbnew();

  mrb_data_init(self, context, &context->type);

  return self;
}

static mrb_value
hdb_ecode(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);

  return mrb_fixnum_value(tchdbecode(context->hdb));
}

static mrb_value
hdb_tune(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  bool result;
  mrb_int bnum, apow, fpow , opts;

  mrb_get_args(mrb, "iiii", &bnum, &apow, &fpow, &opts);

  result = tchdbtune(context->hdb, bnum, apow, fpow, opts);

  return mrb_bool_value(result);
}

static mrb_value
hdb_set_cache(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  mrb_int rcnum;

  mrb_get_args(mrb, "i", &rcnum);

  return mrb_bool_value(tchdbsetcache(context->hdb, rcnum));
}

static mrb_value
hdb_set_xmsize(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  mrb_int xmsize;

  mrb_get_args(mrb, "i", &xmsize);

  return mrb_bool_value(tchdbsetxmsiz(context->hdb, xmsize));
}

static mrb_value
hdb_open(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  char *path;
  int omode;

  mrb_get_args(mrb, "zi", &path, &omode);

  return mrb_bool_value(tchdbopen(context->hdb, path, omode));
}


static mrb_value
hdb_close(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);

  return mrb_bool_value(tchdbclose(context->hdb));
}

static bool
get_content(mrb_value object, mrb_int *store, void **buf, mrb_int *buf_size)
{
  switch (mrb_type(object)) {
  case MRB_TT_FIXNUM:
    *store = mrb_fixnum(object);
    *buf = store;
    *buf_size = sizeof(*store);
    break;
  case MRB_TT_STRING:
    *buf = RSTRING_PTR(object);
    *buf_size = RSTRING_LEN(object); 
    break;
  default:
    return false;
  }
  return true;
}

static mrb_value
hdb_put(mrb_state *mrb, mrb_value self)
{
  mrb_value key, value;
  mrb_bool sync;
  bool result = false;
  mrb_int args;
  void *kbuf, *vbuf;
  int ksize, vsize;
  mrb_int kint, vint;
  hdb_context *context = DATA_PTR(self);

  args = mrb_get_args(mrb, "oo|b", &key, &value, &sync);
  if (args == 2) {
    sync = true;
  }

  if (!get_content(key, &kint, &kbuf, &ksize)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid type of key");
  }

  if (!get_content(value, &vint, &vbuf, &vsize)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid type of value");
  }

  if (sync) {
    result = tchdbput(context->hdb, kbuf, ksize, vbuf, vsize);
  } else {
    result = tchdbputasync(context->hdb, kbuf, ksize, vbuf, vsize);
  }

  return mrb_bool_value(result);
}

static mrb_value
hdb_out(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  mrb_value key, block, result;
  void *kbuf;
  int ksize;
  mrb_int kint;
  int sp = 0;
  void *value;

  mrb_get_args(mrb, "o|&", &key, &block);

  if (!get_content(key, &kint, &kbuf, &ksize)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid type of key");
  }

  value = tchdbget(context->hdb, kbuf, ksize, &sp);
  if (value == NULL || sp <= 0) {
    if (value) {
      free(value);
    }
    return mrb_nil_value();
  }

  // backup
  result = mrb_str_new(mrb, value, sp);

  if (tchdbout(context->hdb, kbuf, ksize)) {
    if (!mrb_nil_p(block)) {
     // mrb_protect(mrb, result);
      mrb_yield(mrb, block, result);
    }
    return result;
  } else {
    return mrb_nil_value();
  }
}

static mrb_value
hdb_get(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  mrb_value key, result;
  void *kbuf;
  int ksize;
  mrb_int kint;
  int sp = 0;
  void *value;


  mrb_get_args(mrb, "o", &key);

  if (!get_content(key, &kint, &kbuf, &ksize)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid type of key");
  }

  value = tchdbget(context->hdb, kbuf, ksize, &sp);
  if (value == NULL || sp <= 0) {
    if (value) {
      free(value);
    }
    return mrb_nil_value();
  }

  result = mrb_str_new(mrb, value, sp);
  free(value);
 
  return result; 
}

static mrb_value
hdb_value_size(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  mrb_value key;
  void *kbuf;
  int ksize;
  mrb_int kint;
  int result;

  mrb_get_args(mrb, "o", &key);

  if (!get_content(key, &kint, &kbuf, &ksize)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "invalid type of key");
  }

  result = tchdbvsiz(context->hdb, kbuf, ksize);

  return mrb_fixnum_value(result);
}

static mrb_value
hdb_sync(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);

  return mrb_bool_value(tchdbsync(context->hdb));
}

static mrb_value
hdb_optimize(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  bool result;
  mrb_int bnum, apow, fpow , opts;


  mrb_get_args(mrb, "iiii", &bnum, &apow, &fpow, &opts);

  result = tchdboptimize(context->hdb, bnum, apow, fpow, opts);

  return mrb_bool_value(result);
}


static mrb_value
hdb_vanish(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);

  return mrb_bool_value(tchdbvanish(context->hdb));
}

static mrb_value
hdb_copy(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  char *path;

  mrb_get_args(mrb, "z", &path);

  return mrb_bool_value(tchdbcopy(context->hdb, path));
}

static mrb_value
hdb_path(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  const char *path;

  path = tchdbpath(context->hdb);
  if (!path) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "internal error");
  }

  return mrb_str_new_static(mrb, path, strlen(path));
}

static mrb_value
hdb_record_num(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  uint64_t records = tchdbrnum(context->hdb);

  return mrb_fixnum_value(records);
}

static mrb_value
hdb_filesize(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  uint64_t size = tchdbfsiz(context->hdb);

  return mrb_fixnum_value(size);
}

static mrb_value
hdb_assoc(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  void *kbuf;
  int ksize;
  mrb_int kint;
  mrb_value ary;
  int sp;
  void *value;
  mrb_value key, result;

  mrb_get_args(mrb, "o", &key);

  if (!get_content(key, &kint, &kbuf, &ksize)) {
    return mrb_nil_value();
  }

  value = tchdbget(context->hdb, kbuf, ksize, &sp);
  if (value == NULL || sp <= 0) {
    if (value) {
      free(value);
    }
    return mrb_nil_value();
  }

  result = mrb_str_new(mrb, value, sp);
  free(value);

  ary = mrb_ary_new_capa(mrb, 2); 
  mrb_ary_push(mrb, ary, key);
  mrb_ary_push(mrb, ary, result);

  return ary; 
}

static mrb_value
hdb_empty_(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  uint64_t records = tchdbrnum(context->hdb);

  return mrb_bool_value(records == 0);
}

static mrb_value
hdb_check_key(mrb_state *mrb, mrb_value self)
{
  hdb_context *context = DATA_PTR(self);
  void *kbuf;
  int ksize;
  mrb_int kint;
  mrb_value key;

  mrb_get_args(mrb, "o", &key);

  if (!get_content(key, &kint, &kbuf, &ksize)) {
    return mrb_nil_value();
  }

  return mrb_bool_value(tchdbvsiz(context->hdb, kbuf, ksize) >= 0);
}

enum {
  EACH_KEY = 1,
  EACH_VALUE = 2,
  EACH_BOTH = 3,
};

/// this function is inspired by gem version of each
static mrb_value
hdb_each_common(mrb_state *mrb, mrb_value self, int mode)
{
  hdb_context *context = DATA_PTR(self);
  mrb_value block;
  TCXSTR *kxstr, *vxstr;

  mrb_get_args(mrb, "&", &block);
  if (mrb_nil_p(block)) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "block must be specified");
  }

  kxstr = tcxstrnew();
  vxstr = tcxstrnew();

  tchdbiterinit(context->hdb);

  while (tchdbiternext3(context->hdb, kxstr, vxstr)) {
    mrb_int argc;
    mrb_value argv[2];
    switch (mode) {
    case EACH_KEY:
	argc = 1;
	argv[0] = mrb_str_new(mrb, tcxstrptr(kxstr), tcxstrsize(kxstr));
	break;
    case EACH_VALUE:
	argc = 1;
	argv[0] = mrb_str_new(mrb, tcxstrptr(vxstr), tcxstrsize(vxstr));
	break;
    case EACH_BOTH:
	argc = 2;
	argv[0] = mrb_str_new(mrb, tcxstrptr(kxstr), tcxstrsize(kxstr));
	argv[1] = mrb_str_new(mrb, tcxstrptr(vxstr), tcxstrsize(vxstr));
	break;
    default:
	// should i write in case of this? no, I don't think so.
	// 'cause this function is file scope function and I can control everything.
	break;
    }
    mrb_yield_argv(mrb, block, argc, &argv[0]); 
  }

  // XXX if an exception is caused between new and del, these two values
  // could cause memory leak? I'm not sure because Im' not an expert for
  // mruby but I believe so. SHOULD fix this.
  tcxstrdel(vxstr);
  tcxstrdel(kxstr);

  return self; 
}

static mrb_value
hdb_each(mrb_state *mrb, mrb_value self)
{
  return hdb_each_common(mrb, self, EACH_BOTH);
}

static mrb_value
hdb_each_key(mrb_state *mrb, mrb_value self)
{
  return hdb_each_common(mrb, self, EACH_KEY);
}

static mrb_value
hdb_each_value(mrb_state *mrb, mrb_value self)
{
  return hdb_each_common(mrb, self, EACH_VALUE);
}



void
mrb_mruby_tokyocabinet_gem_init(mrb_state* mrb) {
  struct RClass *c = mrb_define_class(mrb, "Hdb", mrb->object_class);
  MRB_SET_INSTANCE_TT(c, MRB_TT_DATA);

  mrb_define_method(mrb, c, "initialize", hdb_initialize, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "ecode", hdb_ecode, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "tune", hdb_tune, MRB_ARGS_REQ(4));
  mrb_define_method(mrb, c, "set_cache", hdb_set_cache, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "set_xmsize", hdb_set_xmsize, MRB_ARGS_REQ(1));

  mrb_define_method(mrb, c, "open", hdb_open, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, c, "close", hdb_close, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "put", hdb_put, MRB_ARGS_REQ(2)|MRB_ARGS_OPT(1));
  mrb_define_method(mrb, c, "out", hdb_out, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "get", hdb_get, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "vsize", hdb_value_size, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "sync", hdb_sync, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "optimize", hdb_optimize, MRB_ARGS_REQ(4));
  mrb_define_method(mrb, c, "vanish", hdb_vanish, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "copy", hdb_copy, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "path", hdb_path, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "rnum", hdb_record_num, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "fize", hdb_filesize, MRB_ARGS_NONE());

  // interfaces for hash compliant 
  
  mrb_define_method(mrb, c, "[]", hdb_get, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "[]=", hdb_put, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, c, "store", hdb_put, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, c, "assoc", hdb_assoc, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, c, "delete", hdb_out, MRB_ARGS_REQ(1)|MRB_ARGS_OPT(1));

  mrb_define_method(mrb, c, "empty?", hdb_empty_, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "has_key?", hdb_check_key, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "include?", hdb_check_key, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "member?", hdb_check_key, MRB_ARGS_REQ(1));

  mrb_define_method(mrb, c, "each", hdb_each, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "each_pair", hdb_each, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "each_key", hdb_each_key, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, c, "each_value", hdb_each_value, MRB_ARGS_REQ(1));

  mrb_define_method(mrb, c, "length", hdb_record_num, MRB_ARGS_NONE());
  mrb_define_method(mrb, c, "size", hdb_record_num, MRB_ARGS_NONE());


  mrb_define_const(mrb, c, "TLARGE",   mrb_fixnum_value(HDBTLARGE));
  mrb_define_const(mrb, c, "TDEFLATE", mrb_fixnum_value(HDBTDEFLATE));
  mrb_define_const(mrb, c, "TBZIP",    mrb_fixnum_value(HDBTBZIP));
  mrb_define_const(mrb, c, "TTCBS",    mrb_fixnum_value(HDBTTCBS));
  mrb_define_const(mrb, c, "TEXCODEC", mrb_fixnum_value(HDBTEXCODEC));

  mrb_define_const(mrb, c, "OREADER", mrb_fixnum_value(HDBOREADER));
  mrb_define_const(mrb, c, "OWRITER", mrb_fixnum_value(HDBOWRITER));
  mrb_define_const(mrb, c, "OCREATE", mrb_fixnum_value(HDBOCREAT));
  mrb_define_const(mrb, c, "OTRUNC",  mrb_fixnum_value(HDBOTRUNC));
  mrb_define_const(mrb, c, "ONOLOCK", mrb_fixnum_value(HDBONOLCK));
  mrb_define_const(mrb, c, "OLOCKNB", mrb_fixnum_value(HDBOLCKNB));
  mrb_define_const(mrb, c, "OOTSYNC", mrb_fixnum_value(HDBOTSYNC));
}

void
mrb_mruby_tokyocabinet_gem_final(mrb_state* mrb) {
  /* finalizer */
}
