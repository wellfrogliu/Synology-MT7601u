#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/pm.h>
#include <linux/bitops.h>
#include <linux/debugfs.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/consumer.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <sound/core.h>
#include <sound/jack.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-dpcm.h>
#include <sound/soc-topology.h>
#include <sound/initval.h>

#if defined(MY_ABC_HERE)
#else  
#define CREATE_TRACE_POINTS
#include <trace/events/asoc.h>
#endif  

#define NAME_SIZE	32

#ifdef CONFIG_DEBUG_FS
struct dentry *snd_soc_debugfs_root;
EXPORT_SYMBOL_GPL(snd_soc_debugfs_root);
#endif

static DEFINE_MUTEX(client_mutex);
static LIST_HEAD(platform_list);
static LIST_HEAD(codec_list);
static LIST_HEAD(component_list);

static int pmdown_time = 5000;
module_param(pmdown_time, int, 0);
MODULE_PARM_DESC(pmdown_time, "DAPM stream powerdown time (msecs)");

static int min_bytes_needed(unsigned long val)
{
	int c = 0;
	int i;

	for (i = (sizeof val * 8) - 1; i >= 0; --i, ++c)
		if (val & (1UL << i))
			break;
	c = (sizeof val * 8) - c;
	if (!c || (c % 8))
		c = (c + 8) / 8;
	else
		c /= 8;
	return c;
}

static int format_register_str(struct snd_soc_codec *codec,
			       unsigned int reg, char *buf, size_t len)
{
	int wordsize = min_bytes_needed(codec->driver->reg_cache_size) * 2;
	int regsize = codec->driver->reg_word_size * 2;
	int ret;

	if (wordsize + regsize + 2 + 1 != len)
		return -EINVAL;

	sprintf(buf, "%.*x: ", wordsize, reg);
	buf += wordsize + 2;

	ret = snd_soc_read(codec, reg);
	if (ret < 0)
		memset(buf, 'X', regsize);
	else
		sprintf(buf, "%.*x", regsize, ret);
	buf[regsize] = '\n';
	 
	return 0;
}

static ssize_t soc_codec_reg_show(struct snd_soc_codec *codec, char *buf,
				  size_t count, loff_t pos)
{
	int i, step = 1;
	int wordsize, regsize;
	int len;
	size_t total = 0;
	loff_t p = 0;

	wordsize = min_bytes_needed(codec->driver->reg_cache_size) * 2;
	regsize = codec->driver->reg_word_size * 2;

	len = wordsize + regsize + 2 + 1;

	if (!codec->driver->reg_cache_size)
		return 0;

	if (codec->driver->reg_cache_step)
		step = codec->driver->reg_cache_step;

	for (i = 0; i < codec->driver->reg_cache_size; i += step) {
		 
		if (p >= pos) {
			if (total + len >= count - 1)
				break;
			format_register_str(codec, i, buf + total, len);
			total += len;
		}
		p += len;
	}

	total = min(total, count - 1);

	return total;
}

static ssize_t codec_reg_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct snd_soc_pcm_runtime *rtd = dev_get_drvdata(dev);

	return soc_codec_reg_show(rtd->codec, buf, PAGE_SIZE, 0);
}

static DEVICE_ATTR(codec_reg, 0444, codec_reg_show, NULL);

static ssize_t pmdown_time_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct snd_soc_pcm_runtime *rtd = dev_get_drvdata(dev);

	return sprintf(buf, "%ld\n", rtd->pmdown_time);
}

static ssize_t pmdown_time_set(struct device *dev,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct snd_soc_pcm_runtime *rtd = dev_get_drvdata(dev);
	int ret;

	ret = kstrtol(buf, 10, &rtd->pmdown_time);
	if (ret)
		return ret;

	return count;
}

static DEVICE_ATTR(pmdown_time, 0644, pmdown_time_show, pmdown_time_set);

static struct attribute *soc_dev_attrs[] = {
	&dev_attr_codec_reg.attr,
	&dev_attr_pmdown_time.attr,
	NULL
};

static umode_t soc_dev_attr_is_visible(struct kobject *kobj,
				       struct attribute *attr, int idx)
{
	struct device *dev = kobj_to_dev(kobj);
	struct snd_soc_pcm_runtime *rtd = dev_get_drvdata(dev);

	if (attr == &dev_attr_pmdown_time.attr)
		return attr->mode;  
	return rtd->codec ? attr->mode : 0;  
}

static const struct attribute_group soc_dapm_dev_group = {
	.attrs = soc_dapm_dev_attrs,
	.is_visible = soc_dev_attr_is_visible,
};

static const struct attribute_group soc_dev_roup = {
	.attrs = soc_dev_attrs,
	.is_visible = soc_dev_attr_is_visible,
};

static const struct attribute_group *soc_dev_attr_groups[] = {
	&soc_dapm_dev_group,
	&soc_dev_roup,
	NULL
};

#ifdef CONFIG_DEBUG_FS
static ssize_t codec_reg_read_file(struct file *file, char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	ssize_t ret;
	struct snd_soc_codec *codec = file->private_data;
	char *buf;

	if (*ppos < 0 || !count)
		return -EINVAL;

	buf = kmalloc(count, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = soc_codec_reg_show(codec, buf, count, *ppos);
	if (ret >= 0) {
		if (copy_to_user(user_buf, buf, ret)) {
			kfree(buf);
			return -EFAULT;
		}
		*ppos += ret;
	}

	kfree(buf);
	return ret;
}

static ssize_t codec_reg_write_file(struct file *file,
		const char __user *user_buf, size_t count, loff_t *ppos)
{
	char buf[32];
	size_t buf_size;
	char *start = buf;
	unsigned long reg, value;
	struct snd_soc_codec *codec = file->private_data;
	int ret;

	buf_size = min(count, (sizeof(buf)-1));
	if (copy_from_user(buf, user_buf, buf_size))
		return -EFAULT;
	buf[buf_size] = 0;

	while (*start == ' ')
		start++;
	reg = simple_strtoul(start, &start, 16);
	while (*start == ' ')
		start++;
	ret = kstrtoul(start, 16, &value);
	if (ret)
		return ret;

	add_taint(TAINT_USER, LOCKDEP_NOW_UNRELIABLE);

	snd_soc_write(codec, reg, value);
	return buf_size;
}

static const struct file_operations codec_reg_fops = {
	.open = simple_open,
	.read = codec_reg_read_file,
	.write = codec_reg_write_file,
	.llseek = default_llseek,
};

static void soc_init_component_debugfs(struct snd_soc_component *component)
{
	if (!component->card->debugfs_card_root)
		return;

	if (component->debugfs_prefix) {
		char *name;

		name = kasprintf(GFP_KERNEL, "%s:%s",
			component->debugfs_prefix, component->name);
		if (name) {
			component->debugfs_root = debugfs_create_dir(name,
				component->card->debugfs_card_root);
			kfree(name);
		}
	} else {
		component->debugfs_root = debugfs_create_dir(component->name,
				component->card->debugfs_card_root);
	}

	if (!component->debugfs_root) {
		dev_warn(component->dev,
			"ASoC: Failed to create component debugfs directory\n");
		return;
	}

	snd_soc_dapm_debugfs_init(snd_soc_component_get_dapm(component),
		component->debugfs_root);

	if (component->init_debugfs)
		component->init_debugfs(component);
}

static void soc_cleanup_component_debugfs(struct snd_soc_component *component)
{
	debugfs_remove_recursive(component->debugfs_root);
}

static void soc_init_codec_debugfs(struct snd_soc_component *component)
{
	struct snd_soc_codec *codec = snd_soc_component_to_codec(component);

	codec->debugfs_reg = debugfs_create_file("codec_reg", 0644,
						 codec->component.debugfs_root,
						 codec, &codec_reg_fops);
	if (!codec->debugfs_reg)
		dev_warn(codec->dev,
			"ASoC: Failed to create codec register debugfs file\n");
}

static ssize_t codec_list_read_file(struct file *file, char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	ssize_t len, ret = 0;
	struct snd_soc_codec *codec;

	if (!buf)
		return -ENOMEM;

	mutex_lock(&client_mutex);

	list_for_each_entry(codec, &codec_list, list) {
		len = snprintf(buf + ret, PAGE_SIZE - ret, "%s\n",
			       codec->component.name);
		if (len >= 0)
			ret += len;
		if (ret > PAGE_SIZE) {
			ret = PAGE_SIZE;
			break;
		}
	}

	mutex_unlock(&client_mutex);

	if (ret >= 0)
		ret = simple_read_from_buffer(user_buf, count, ppos, buf, ret);

	kfree(buf);

	return ret;
}

static const struct file_operations codec_list_fops = {
	.read = codec_list_read_file,
	.llseek = default_llseek, 
};

static ssize_t dai_list_read_file(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	ssize_t len, ret = 0;
	struct snd_soc_component *component;
	struct snd_soc_dai *dai;

	if (!buf)
		return -ENOMEM;

	mutex_lock(&client_mutex);

	list_for_each_entry(component, &component_list, list) {
		list_for_each_entry(dai, &component->dai_list, list) {
			len = snprintf(buf + ret, PAGE_SIZE - ret, "%s\n",
				dai->name);
			if (len >= 0)
				ret += len;
			if (ret > PAGE_SIZE) {
				ret = PAGE_SIZE;
				break;
			}
		}
	}

	mutex_unlock(&client_mutex);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, ret);

	kfree(buf);

	return ret;
}

static const struct file_operations dai_list_fops = {
	.read = dai_list_read_file,
	.llseek = default_llseek, 
};

static ssize_t platform_list_read_file(struct file *file,
				       char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	ssize_t len, ret = 0;
	struct snd_soc_platform *platform;

	if (!buf)
		return -ENOMEM;

	mutex_lock(&client_mutex);

	list_for_each_entry(platform, &platform_list, list) {
		len = snprintf(buf + ret, PAGE_SIZE - ret, "%s\n",
			       platform->component.name);
		if (len >= 0)
			ret += len;
		if (ret > PAGE_SIZE) {
			ret = PAGE_SIZE;
			break;
		}
	}

	mutex_unlock(&client_mutex);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, ret);

	kfree(buf);

	return ret;
}

static const struct file_operations platform_list_fops = {
	.read = platform_list_read_file,
	.llseek = default_llseek, 
};

static void soc_init_card_debugfs(struct snd_soc_card *card)
{
	if (!snd_soc_debugfs_root)
		return;

	card->debugfs_card_root = debugfs_create_dir(card->name,
						     snd_soc_debugfs_root);
	if (!card->debugfs_card_root) {
		dev_warn(card->dev,
			 "ASoC: Failed to create card debugfs directory\n");
		return;
	}

	card->debugfs_pop_time = debugfs_create_u32("dapm_pop_time", 0644,
						    card->debugfs_card_root,
						    &card->pop_time);
	if (!card->debugfs_pop_time)
		dev_warn(card->dev,
		       "ASoC: Failed to create pop time debugfs file\n");
}

static void soc_cleanup_card_debugfs(struct snd_soc_card *card)
{
	debugfs_remove_recursive(card->debugfs_card_root);
}

static void snd_soc_debugfs_init(void)
{
	snd_soc_debugfs_root = debugfs_create_dir("asoc", NULL);
	if (IS_ERR(snd_soc_debugfs_root) || !snd_soc_debugfs_root) {
		pr_warn("ASoC: Failed to create debugfs directory\n");
		snd_soc_debugfs_root = NULL;
		return;
	}

	if (!debugfs_create_file("codecs", 0444, snd_soc_debugfs_root, NULL,
				 &codec_list_fops))
		pr_warn("ASoC: Failed to create CODEC list debugfs file\n");

	if (!debugfs_create_file("dais", 0444, snd_soc_debugfs_root, NULL,
				 &dai_list_fops))
		pr_warn("ASoC: Failed to create DAI list debugfs file\n");

	if (!debugfs_create_file("platforms", 0444, snd_soc_debugfs_root, NULL,
				 &platform_list_fops))
		pr_warn("ASoC: Failed to create platform list debugfs file\n");
}

static void snd_soc_debugfs_exit(void)
{
	debugfs_remove_recursive(snd_soc_debugfs_root);
}

#else

#define soc_init_codec_debugfs NULL

static inline void soc_init_component_debugfs(
	struct snd_soc_component *component)
{
}

static inline void soc_cleanup_component_debugfs(
	struct snd_soc_component *component)
{
}

static inline void soc_init_card_debugfs(struct snd_soc_card *card)
{
}

static inline void soc_cleanup_card_debugfs(struct snd_soc_card *card)
{
}

static inline void snd_soc_debugfs_init(void)
{
}

static inline void snd_soc_debugfs_exit(void)
{
}

#endif

struct snd_pcm_substream *snd_soc_get_dai_substream(struct snd_soc_card *card,
		const char *dai_link, int stream)
{
	int i;

	for (i = 0; i < card->num_links; i++) {
		if (card->rtd[i].dai_link->no_pcm &&
			!strcmp(card->rtd[i].dai_link->name, dai_link))
			return card->rtd[i].pcm->streams[stream].substream;
	}
	dev_dbg(card->dev, "ASoC: failed to find dai link %s\n", dai_link);
	return NULL;
}
EXPORT_SYMBOL_GPL(snd_soc_get_dai_substream);

struct snd_soc_pcm_runtime *snd_soc_get_pcm_runtime(struct snd_soc_card *card,
		const char *dai_link)
{
	int i;

	for (i = 0; i < card->num_links; i++) {
		if (!strcmp(card->rtd[i].dai_link->name, dai_link))
			return &card->rtd[i];
	}
	dev_dbg(card->dev, "ASoC: failed to find rtd %s\n", dai_link);
	return NULL;
}
EXPORT_SYMBOL_GPL(snd_soc_get_pcm_runtime);

static void codec2codec_close_delayed_work(struct work_struct *work)
{
	 
}

#ifdef CONFIG_PM_SLEEP
 
int snd_soc_suspend(struct device *dev)
{
	struct snd_soc_card *card = dev_get_drvdata(dev);
	struct snd_soc_codec *codec;
	int i, j;

	if (!card->instantiated)
		return 0;

	snd_power_lock(card->snd_card);
	snd_power_wait(card->snd_card, SNDRV_CTL_POWER_D0);
	snd_power_unlock(card->snd_card);

	snd_power_change_state(card->snd_card, SNDRV_CTL_POWER_D3hot);

	for (i = 0; i < card->num_rtd; i++) {

		if (card->rtd[i].dai_link->ignore_suspend)
			continue;

		for (j = 0; j < card->rtd[i].num_codecs; j++) {
			struct snd_soc_dai *dai = card->rtd[i].codec_dais[j];
			struct snd_soc_dai_driver *drv = dai->driver;

			if (drv->ops->digital_mute && dai->playback_active)
				drv->ops->digital_mute(dai, 1);
		}
	}

	for (i = 0; i < card->num_rtd; i++) {
		if (card->rtd[i].dai_link->ignore_suspend)
			continue;

		snd_pcm_suspend_all(card->rtd[i].pcm);
	}

	if (card->suspend_pre)
		card->suspend_pre(card);

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_dai *cpu_dai = card->rtd[i].cpu_dai;

		if (card->rtd[i].dai_link->ignore_suspend)
			continue;

		if (cpu_dai->driver->suspend && !cpu_dai->driver->bus_control)
			cpu_dai->driver->suspend(cpu_dai);
	}

	for (i = 0; i < card->num_rtd; i++)
		flush_delayed_work(&card->rtd[i].delayed_work);

	for (i = 0; i < card->num_rtd; i++) {

		if (card->rtd[i].dai_link->ignore_suspend)
			continue;

		snd_soc_dapm_stream_event(&card->rtd[i],
					  SNDRV_PCM_STREAM_PLAYBACK,
					  SND_SOC_DAPM_STREAM_SUSPEND);

		snd_soc_dapm_stream_event(&card->rtd[i],
					  SNDRV_PCM_STREAM_CAPTURE,
					  SND_SOC_DAPM_STREAM_SUSPEND);
	}

	dapm_mark_endpoints_dirty(card);
	snd_soc_dapm_sync(&card->dapm);

	list_for_each_entry(codec, &card->codec_dev_list, card_list) {
		struct snd_soc_dapm_context *dapm = snd_soc_codec_get_dapm(codec);

		if (!codec->suspended) {
			switch (snd_soc_dapm_get_bias_level(dapm)) {
			case SND_SOC_BIAS_STANDBY:
				 
				if (dapm->idle_bias_off) {
					dev_dbg(codec->dev,
						"ASoC: idle_bias_off CODEC on over suspend\n");
					break;
				}

			case SND_SOC_BIAS_OFF:
				if (codec->driver->suspend)
					codec->driver->suspend(codec);
				codec->suspended = 1;
				if (codec->component.regmap)
					regcache_mark_dirty(codec->component.regmap);
				 
				pinctrl_pm_select_sleep_state(codec->dev);
				break;
			default:
				dev_dbg(codec->dev,
					"ASoC: CODEC is on over suspend\n");
				break;
			}
		}
	}

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_dai *cpu_dai = card->rtd[i].cpu_dai;

		if (card->rtd[i].dai_link->ignore_suspend)
			continue;

		if (cpu_dai->driver->suspend && cpu_dai->driver->bus_control)
			cpu_dai->driver->suspend(cpu_dai);

		pinctrl_pm_select_sleep_state(cpu_dai->dev);
	}

	if (card->suspend_post)
		card->suspend_post(card);

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_suspend);

static void soc_resume_deferred(struct work_struct *work)
{
	struct snd_soc_card *card =
			container_of(work, struct snd_soc_card, deferred_resume_work);
	struct snd_soc_codec *codec;
	int i, j;

	dev_dbg(card->dev, "ASoC: starting resume work\n");

	snd_power_change_state(card->snd_card, SNDRV_CTL_POWER_D2);

	if (card->resume_pre)
		card->resume_pre(card);

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_dai *cpu_dai = card->rtd[i].cpu_dai;

		if (card->rtd[i].dai_link->ignore_suspend)
			continue;

		if (cpu_dai->driver->resume && cpu_dai->driver->bus_control)
			cpu_dai->driver->resume(cpu_dai);
	}

	list_for_each_entry(codec, &card->codec_dev_list, card_list) {
		if (codec->suspended) {
			if (codec->driver->resume)
				codec->driver->resume(codec);
			codec->suspended = 0;
		}
	}

	for (i = 0; i < card->num_rtd; i++) {

		if (card->rtd[i].dai_link->ignore_suspend)
			continue;

		snd_soc_dapm_stream_event(&card->rtd[i],
					  SNDRV_PCM_STREAM_PLAYBACK,
					  SND_SOC_DAPM_STREAM_RESUME);

		snd_soc_dapm_stream_event(&card->rtd[i],
					  SNDRV_PCM_STREAM_CAPTURE,
					  SND_SOC_DAPM_STREAM_RESUME);
	}

	for (i = 0; i < card->num_rtd; i++) {

		if (card->rtd[i].dai_link->ignore_suspend)
			continue;

		for (j = 0; j < card->rtd[i].num_codecs; j++) {
			struct snd_soc_dai *dai = card->rtd[i].codec_dais[j];
			struct snd_soc_dai_driver *drv = dai->driver;

			if (drv->ops->digital_mute && dai->playback_active)
				drv->ops->digital_mute(dai, 0);
		}
	}

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_dai *cpu_dai = card->rtd[i].cpu_dai;

		if (card->rtd[i].dai_link->ignore_suspend)
			continue;

		if (cpu_dai->driver->resume && !cpu_dai->driver->bus_control)
			cpu_dai->driver->resume(cpu_dai);
	}

	if (card->resume_post)
		card->resume_post(card);

	dev_dbg(card->dev, "ASoC: resume work completed\n");

	dapm_mark_endpoints_dirty(card);
	snd_soc_dapm_sync(&card->dapm);

	snd_power_change_state(card->snd_card, SNDRV_CTL_POWER_D0);
}

int snd_soc_resume(struct device *dev)
{
	struct snd_soc_card *card = dev_get_drvdata(dev);
	bool bus_control = false;
	int i;

	if (!card->instantiated)
		return 0;

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_pcm_runtime *rtd = &card->rtd[i];
		struct snd_soc_dai **codec_dais = rtd->codec_dais;
		struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
		int j;

		if (cpu_dai->active)
			pinctrl_pm_select_default_state(cpu_dai->dev);

		for (j = 0; j < rtd->num_codecs; j++) {
			struct snd_soc_dai *codec_dai = codec_dais[j];
			if (codec_dai->active)
				pinctrl_pm_select_default_state(codec_dai->dev);
		}
	}

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_dai *cpu_dai = card->rtd[i].cpu_dai;
		bus_control |= cpu_dai->driver->bus_control;
	}
	if (bus_control) {
		dev_dbg(dev, "ASoC: Resuming control bus master immediately\n");
		soc_resume_deferred(&card->deferred_resume_work);
	} else {
		dev_dbg(dev, "ASoC: Scheduling resume work\n");
		if (!schedule_work(&card->deferred_resume_work))
			dev_err(dev, "ASoC: resume work item may be lost\n");
	}

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_resume);
#else
#define snd_soc_suspend NULL
#define snd_soc_resume NULL
#endif

static const struct snd_soc_dai_ops null_dai_ops = {
};

static struct snd_soc_component *soc_find_component(
	const struct device_node *of_node, const char *name)
{
	struct snd_soc_component *component;

	lockdep_assert_held(&client_mutex);

	list_for_each_entry(component, &component_list, list) {
		if (of_node) {
			if (component->dev->of_node == of_node)
				return component;
		} else if (strcmp(component->name, name) == 0) {
			return component;
		}
	}

	return NULL;
}

static struct snd_soc_dai *snd_soc_find_dai(
	const struct snd_soc_dai_link_component *dlc)
{
	struct snd_soc_component *component;
	struct snd_soc_dai *dai;
	struct device_node *component_of_node;

	lockdep_assert_held(&client_mutex);

	list_for_each_entry(component, &component_list, list) {
		component_of_node = component->dev->of_node;
		if (!component_of_node && component->dev->parent)
			component_of_node = component->dev->parent->of_node;

		if (dlc->of_node && component_of_node != dlc->of_node)
			continue;
		if (dlc->name && strcmp(component->name, dlc->name))
			continue;
		list_for_each_entry(dai, &component->dai_list, list) {
			if (dlc->dai_name && strcmp(dai->name, dlc->dai_name))
				continue;

			return dai;
		}
	}

	return NULL;
}

static int soc_bind_dai_link(struct snd_soc_card *card, int num)
{
	struct snd_soc_dai_link *dai_link = &card->dai_link[num];
	struct snd_soc_pcm_runtime *rtd = &card->rtd[num];
	struct snd_soc_dai_link_component *codecs = dai_link->codecs;
	struct snd_soc_dai_link_component cpu_dai_component;
	struct snd_soc_dai **codec_dais = rtd->codec_dais;
	struct snd_soc_platform *platform;
	const char *platform_name;
	int i;

	dev_dbg(card->dev, "ASoC: binding %s at idx %d\n", dai_link->name, num);

	cpu_dai_component.name = dai_link->cpu_name;
	cpu_dai_component.of_node = dai_link->cpu_of_node;
	cpu_dai_component.dai_name = dai_link->cpu_dai_name;
	rtd->cpu_dai = snd_soc_find_dai(&cpu_dai_component);
	if (!rtd->cpu_dai) {
		dev_err(card->dev, "ASoC: CPU DAI %s not registered\n",
			dai_link->cpu_dai_name);
		return -EPROBE_DEFER;
	}

	rtd->num_codecs = dai_link->num_codecs;

	for (i = 0; i < rtd->num_codecs; i++) {
		codec_dais[i] = snd_soc_find_dai(&codecs[i]);
		if (!codec_dais[i]) {
			dev_err(card->dev, "ASoC: CODEC DAI %s not registered\n",
				codecs[i].dai_name);
			return -EPROBE_DEFER;
		}
	}

	rtd->codec_dai = codec_dais[0];
	rtd->codec = rtd->codec_dai->codec;

	platform_name = dai_link->platform_name;
	if (!platform_name && !dai_link->platform_of_node)
		platform_name = "snd-soc-dummy";

	list_for_each_entry(platform, &platform_list, list) {
		if (dai_link->platform_of_node) {
			if (platform->dev->of_node !=
			    dai_link->platform_of_node)
				continue;
		} else {
			if (strcmp(platform->component.name, platform_name))
				continue;
		}

		rtd->platform = platform;
	}
	if (!rtd->platform) {
		dev_err(card->dev, "ASoC: platform %s not registered\n",
			dai_link->platform_name);
		return -EPROBE_DEFER;
	}

	card->num_rtd++;

	return 0;
}

static void soc_remove_component(struct snd_soc_component *component)
{
	if (!component->card)
		return;

	if (component->codec)
		list_del(&component->codec->card_list);

	if (component->remove)
		component->remove(component);

	snd_soc_dapm_free(snd_soc_component_get_dapm(component));

	soc_cleanup_component_debugfs(component);
	component->card = NULL;
	module_put(component->dev->driver->owner);
}

static void soc_remove_dai(struct snd_soc_dai *dai, int order)
{
	int err;

	if (dai && dai->probed &&
			dai->driver->remove_order == order) {
		if (dai->driver->remove) {
			err = dai->driver->remove(dai);
			if (err < 0)
				dev_err(dai->dev,
					"ASoC: failed to remove %s: %d\n",
					dai->name, err);
		}
		dai->probed = 0;
	}
}

static void soc_remove_link_dais(struct snd_soc_card *card, int num, int order)
{
	struct snd_soc_pcm_runtime *rtd = &card->rtd[num];
	int i;

	if (rtd->dev_registered) {
		device_unregister(rtd->dev);
		rtd->dev_registered = 0;
	}

	for (i = 0; i < rtd->num_codecs; i++)
		soc_remove_dai(rtd->codec_dais[i], order);

	soc_remove_dai(rtd->cpu_dai, order);
}

static void soc_remove_link_components(struct snd_soc_card *card, int num,
				       int order)
{
	struct snd_soc_pcm_runtime *rtd = &card->rtd[num];
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	struct snd_soc_platform *platform = rtd->platform;
	struct snd_soc_component *component;
	int i;

	if (platform && platform->component.driver->remove_order == order)
		soc_remove_component(&platform->component);

	for (i = 0; i < rtd->num_codecs; i++) {
		component = rtd->codec_dais[i]->component;
		if (component->driver->remove_order == order)
			soc_remove_component(component);
	}

	if (cpu_dai) {
		if (cpu_dai->component->driver->remove_order == order)
			soc_remove_component(cpu_dai->component);
	}
}

static void soc_remove_dai_links(struct snd_soc_card *card)
{
	int dai, order;

	for (order = SND_SOC_COMP_ORDER_FIRST; order <= SND_SOC_COMP_ORDER_LAST;
			order++) {
		for (dai = 0; dai < card->num_rtd; dai++)
			soc_remove_link_dais(card, dai, order);
	}

	for (order = SND_SOC_COMP_ORDER_FIRST; order <= SND_SOC_COMP_ORDER_LAST;
			order++) {
		for (dai = 0; dai < card->num_rtd; dai++)
			soc_remove_link_components(card, dai, order);
	}

	card->num_rtd = 0;
}

static void soc_set_name_prefix(struct snd_soc_card *card,
				struct snd_soc_component *component)
{
	int i;

	if (card->codec_conf == NULL)
		return;

	for (i = 0; i < card->num_configs; i++) {
		struct snd_soc_codec_conf *map = &card->codec_conf[i];
		if (map->of_node && component->dev->of_node != map->of_node)
			continue;
		if (map->dev_name && strcmp(component->name, map->dev_name))
			continue;
		component->name_prefix = map->name_prefix;
		break;
	}
}

static int soc_probe_component(struct snd_soc_card *card,
	struct snd_soc_component *component)
{
	struct snd_soc_dapm_context *dapm = snd_soc_component_get_dapm(component);
	struct snd_soc_dai *dai;
	int ret;

	if (!strcmp(component->name, "snd-soc-dummy"))
		return 0;

	if (component->card) {
		if (component->card != card) {
			dev_err(component->dev,
				"Trying to bind component to card \"%s\" but is already bound to card \"%s\"\n",
				card->name, component->card->name);
			return -ENODEV;
		}
		return 0;
	}

	if (!try_module_get(component->dev->driver->owner))
		return -ENODEV;

	component->card = card;
	dapm->card = card;
	soc_set_name_prefix(card, component);

	soc_init_component_debugfs(component);

	if (component->dapm_widgets) {
		ret = snd_soc_dapm_new_controls(dapm, component->dapm_widgets,
			component->num_dapm_widgets);

		if (ret != 0) {
			dev_err(component->dev,
				"Failed to create new controls %d\n", ret);
			goto err_probe;
		}
	}

	list_for_each_entry(dai, &component->dai_list, list) {
		ret = snd_soc_dapm_new_dai_widgets(dapm, dai);
		if (ret != 0) {
			dev_err(component->dev,
				"Failed to create DAI widgets %d\n", ret);
			goto err_probe;
		}
	}

	if (component->probe) {
		ret = component->probe(component);
		if (ret < 0) {
			dev_err(component->dev,
				"ASoC: failed to probe component %d\n", ret);
			goto err_probe;
		}

		WARN(dapm->idle_bias_off &&
			dapm->bias_level != SND_SOC_BIAS_OFF,
			"codec %s can not start from non-off bias with idle_bias_off==1\n",
			component->name);
	}

	if (component->controls)
		snd_soc_add_component_controls(component, component->controls,
				     component->num_controls);
	if (component->dapm_routes)
		snd_soc_dapm_add_routes(dapm, component->dapm_routes,
					component->num_dapm_routes);

	list_add(&dapm->list, &card->dapm_list);

	if (component->codec)
		list_add(&component->codec->card_list, &card->codec_dev_list);

	return 0;

err_probe:
	soc_cleanup_component_debugfs(component);
	component->card = NULL;
	module_put(component->dev->driver->owner);

	return ret;
}

static void rtd_release(struct device *dev)
{
	kfree(dev);
}

static int soc_post_component_init(struct snd_soc_pcm_runtime *rtd,
	const char *name)
{
	int ret = 0;

	rtd->dev = kzalloc(sizeof(struct device), GFP_KERNEL);
	if (!rtd->dev)
		return -ENOMEM;
	device_initialize(rtd->dev);
	rtd->dev->parent = rtd->card->dev;
	rtd->dev->release = rtd_release;
	rtd->dev->groups = soc_dev_attr_groups;
	dev_set_name(rtd->dev, "%s", name);
	dev_set_drvdata(rtd->dev, rtd);
	mutex_init(&rtd->pcm_mutex);
	INIT_LIST_HEAD(&rtd->dpcm[SNDRV_PCM_STREAM_PLAYBACK].be_clients);
	INIT_LIST_HEAD(&rtd->dpcm[SNDRV_PCM_STREAM_CAPTURE].be_clients);
	INIT_LIST_HEAD(&rtd->dpcm[SNDRV_PCM_STREAM_PLAYBACK].fe_clients);
	INIT_LIST_HEAD(&rtd->dpcm[SNDRV_PCM_STREAM_CAPTURE].fe_clients);
	ret = device_add(rtd->dev);
	if (ret < 0) {
		 
		put_device(rtd->dev);
		dev_err(rtd->card->dev,
			"ASoC: failed to register runtime device: %d\n", ret);
		return ret;
	}
	rtd->dev_registered = 1;
	return 0;
}

static int soc_probe_link_components(struct snd_soc_card *card, int num,
				     int order)
{
	struct snd_soc_pcm_runtime *rtd = &card->rtd[num];
	struct snd_soc_platform *platform = rtd->platform;
	struct snd_soc_component *component;
	int i, ret;

	component = rtd->cpu_dai->component;
	if (component->driver->probe_order == order) {
		ret = soc_probe_component(card, component);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < rtd->num_codecs; i++) {
		component = rtd->codec_dais[i]->component;
		if (component->driver->probe_order == order) {
			ret = soc_probe_component(card, component);
			if (ret < 0)
				return ret;
		}
	}

	if (platform->component.driver->probe_order == order) {
		ret = soc_probe_component(card, &platform->component);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int soc_probe_dai(struct snd_soc_dai *dai, int order)
{
	int ret;

	if (!dai->probed && dai->driver->probe_order == order) {
		if (dai->driver->probe) {
			ret = dai->driver->probe(dai);
			if (ret < 0) {
				dev_err(dai->dev,
					"ASoC: failed to probe DAI %s: %d\n",
					dai->name, ret);
				return ret;
			}
		}

		dai->probed = 1;
	}

	return 0;
}

static int soc_link_dai_widgets(struct snd_soc_card *card,
				struct snd_soc_dai_link *dai_link,
				struct snd_soc_pcm_runtime *rtd)
{
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	struct snd_soc_dapm_widget *play_w, *capture_w;
	int ret;

	if (rtd->num_codecs > 1)
		dev_warn(card->dev, "ASoC: Multiple codecs not supported yet\n");

	play_w = codec_dai->playback_widget;
	capture_w = cpu_dai->capture_widget;
	if (play_w && capture_w) {
		ret = snd_soc_dapm_new_pcm(card, dai_link->params,
					   dai_link->num_params, capture_w,
					   play_w);
		if (ret != 0) {
			dev_err(card->dev, "ASoC: Can't link %s to %s: %d\n",
				play_w->name, capture_w->name, ret);
			return ret;
		}
	}

	play_w = cpu_dai->playback_widget;
	capture_w = codec_dai->capture_widget;
	if (play_w && capture_w) {
		ret = snd_soc_dapm_new_pcm(card, dai_link->params,
					   dai_link->num_params, capture_w,
					   play_w);
		if (ret != 0) {
			dev_err(card->dev, "ASoC: Can't link %s to %s: %d\n",
				play_w->name, capture_w->name, ret);
			return ret;
		}
	}

	return 0;
}

static int soc_probe_link_dais(struct snd_soc_card *card, int num, int order)
{
	struct snd_soc_dai_link *dai_link = &card->dai_link[num];
	struct snd_soc_pcm_runtime *rtd = &card->rtd[num];
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	int i, ret;

	dev_dbg(card->dev, "ASoC: probe %s dai link %d late %d\n",
			card->name, num, order);

	rtd->pmdown_time = pmdown_time;

	ret = soc_probe_dai(cpu_dai, order);
	if (ret)
		return ret;

	for (i = 0; i < rtd->num_codecs; i++) {
		ret = soc_probe_dai(rtd->codec_dais[i], order);
		if (ret)
			return ret;
	}

	if (order != SND_SOC_COMP_ORDER_LAST)
		return 0;

	if (dai_link->init) {
		ret = dai_link->init(rtd);
		if (ret < 0) {
			dev_err(card->dev, "ASoC: failed to init %s: %d\n",
				dai_link->name, ret);
			return ret;
		}
	}

	if (dai_link->dai_fmt)
		snd_soc_runtime_set_dai_fmt(rtd, dai_link->dai_fmt);

	ret = soc_post_component_init(rtd, dai_link->name);
	if (ret)
		return ret;

#ifdef CONFIG_DEBUG_FS
	 
	if (dai_link->dynamic)
		soc_dpcm_debugfs_add(rtd);
#endif

	if (cpu_dai->driver->compress_new) {
		 
		ret = cpu_dai->driver->compress_new(rtd, num);
		if (ret < 0) {
			dev_err(card->dev, "ASoC: can't create compress %s\n",
					 dai_link->stream_name);
			return ret;
		}
	} else {

		if (!dai_link->params) {
			 
			ret = soc_new_pcm(rtd, num);
			if (ret < 0) {
				dev_err(card->dev, "ASoC: can't create pcm %s :%d\n",
				       dai_link->stream_name, ret);
				return ret;
			}
		} else {
			INIT_DELAYED_WORK(&rtd->delayed_work,
						codec2codec_close_delayed_work);

			ret = soc_link_dai_widgets(card, dai_link, rtd);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int soc_bind_aux_dev(struct snd_soc_card *card, int num)
{
	struct snd_soc_pcm_runtime *rtd = &card->rtd_aux[num];
	struct snd_soc_aux_dev *aux_dev = &card->aux_dev[num];
	const char *name = aux_dev->codec_name;

	rtd->component = soc_find_component(aux_dev->codec_of_node, name);
	if (!rtd->component) {
		if (aux_dev->codec_of_node)
			name = of_node_full_name(aux_dev->codec_of_node);

		dev_err(card->dev, "ASoC: %s not registered\n", name);
		return -EPROBE_DEFER;
	}

	 rtd->codec = rtd->component->codec;

	return 0;
}

static int soc_probe_aux_dev(struct snd_soc_card *card, int num)
{
	struct snd_soc_pcm_runtime *rtd = &card->rtd_aux[num];
	struct snd_soc_aux_dev *aux_dev = &card->aux_dev[num];
	int ret;

	ret = soc_probe_component(card, rtd->component);
	if (ret < 0)
		return ret;

	if (aux_dev->init) {
		ret = aux_dev->init(rtd->component);
		if (ret < 0) {
			dev_err(card->dev, "ASoC: failed to init %s: %d\n",
				aux_dev->name, ret);
			return ret;
		}
	}

	return soc_post_component_init(rtd, aux_dev->name);
}

static void soc_remove_aux_dev(struct snd_soc_card *card, int num)
{
	struct snd_soc_pcm_runtime *rtd = &card->rtd_aux[num];
	struct snd_soc_component *component = rtd->component;

	if (rtd->dev_registered) {
		device_unregister(rtd->dev);
		rtd->dev_registered = 0;
	}

	if (component)
		soc_remove_component(component);
}

static int snd_soc_init_codec_cache(struct snd_soc_codec *codec)
{
	int ret;

	if (codec->cache_init)
		return 0;

	ret = snd_soc_cache_init(codec);
	if (ret < 0) {
		dev_err(codec->dev,
			"ASoC: Failed to set cache compression type: %d\n",
			ret);
		return ret;
	}
	codec->cache_init = 1;
	return 0;
}

int snd_soc_runtime_set_dai_fmt(struct snd_soc_pcm_runtime *rtd,
	unsigned int dai_fmt)
{
	struct snd_soc_dai **codec_dais = rtd->codec_dais;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	unsigned int i;
	int ret;

	for (i = 0; i < rtd->num_codecs; i++) {
		struct snd_soc_dai *codec_dai = codec_dais[i];

		ret = snd_soc_dai_set_fmt(codec_dai, dai_fmt);
		if (ret != 0 && ret != -ENOTSUPP) {
			dev_warn(codec_dai->dev,
				 "ASoC: Failed to set DAI format: %d\n", ret);
			return ret;
		}
	}

	if (cpu_dai->codec) {
		unsigned int inv_dai_fmt;

		inv_dai_fmt = dai_fmt & ~SND_SOC_DAIFMT_MASTER_MASK;
		switch (dai_fmt & SND_SOC_DAIFMT_MASTER_MASK) {
		case SND_SOC_DAIFMT_CBM_CFM:
			inv_dai_fmt |= SND_SOC_DAIFMT_CBS_CFS;
			break;
		case SND_SOC_DAIFMT_CBM_CFS:
			inv_dai_fmt |= SND_SOC_DAIFMT_CBS_CFM;
			break;
		case SND_SOC_DAIFMT_CBS_CFM:
			inv_dai_fmt |= SND_SOC_DAIFMT_CBM_CFS;
			break;
		case SND_SOC_DAIFMT_CBS_CFS:
			inv_dai_fmt |= SND_SOC_DAIFMT_CBM_CFM;
			break;
		}

		dai_fmt = inv_dai_fmt;
	}

	ret = snd_soc_dai_set_fmt(cpu_dai, dai_fmt);
	if (ret != 0 && ret != -ENOTSUPP) {
		dev_warn(cpu_dai->dev,
			 "ASoC: Failed to set DAI format: %d\n", ret);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_runtime_set_dai_fmt);

static int snd_soc_instantiate_card(struct snd_soc_card *card)
{
	struct snd_soc_codec *codec;
	int ret, i, order;

	mutex_lock(&client_mutex);
	mutex_lock_nested(&card->mutex, SND_SOC_CARD_CLASS_INIT);

	for (i = 0; i < card->num_links; i++) {
		ret = soc_bind_dai_link(card, i);
		if (ret != 0)
			goto base_error;
	}

	for (i = 0; i < card->num_aux_devs; i++) {
		ret = soc_bind_aux_dev(card, i);
		if (ret != 0)
			goto base_error;
	}

	list_for_each_entry(codec, &codec_list, list) {
		if (codec->cache_init)
			continue;
		ret = snd_soc_init_codec_cache(codec);
		if (ret < 0)
			goto base_error;
	}

	ret = snd_card_new(card->dev, SNDRV_DEFAULT_IDX1, SNDRV_DEFAULT_STR1,
			card->owner, 0, &card->snd_card);
	if (ret < 0) {
		dev_err(card->dev,
			"ASoC: can't create sound card for card %s: %d\n",
			card->name, ret);
		goto base_error;
	}

	soc_init_card_debugfs(card);

	card->dapm.bias_level = SND_SOC_BIAS_OFF;
	card->dapm.dev = card->dev;
	card->dapm.card = card;
	list_add(&card->dapm.list, &card->dapm_list);

#ifdef CONFIG_DEBUG_FS
	snd_soc_dapm_debugfs_init(&card->dapm, card->debugfs_card_root);
#endif

#ifdef CONFIG_PM_SLEEP
	 
	INIT_WORK(&card->deferred_resume_work, soc_resume_deferred);
#endif

	if (card->dapm_widgets)
		snd_soc_dapm_new_controls(&card->dapm, card->dapm_widgets,
					  card->num_dapm_widgets);

	if (card->of_dapm_widgets)
		snd_soc_dapm_new_controls(&card->dapm, card->of_dapm_widgets,
					  card->num_of_dapm_widgets);

	if (card->probe) {
		ret = card->probe(card);
		if (ret < 0)
			goto card_probe_error;
	}

	for (order = SND_SOC_COMP_ORDER_FIRST; order <= SND_SOC_COMP_ORDER_LAST;
			order++) {
		for (i = 0; i < card->num_links; i++) {
			ret = soc_probe_link_components(card, i, order);
			if (ret < 0) {
				dev_err(card->dev,
					"ASoC: failed to instantiate card %d\n",
					ret);
				goto probe_dai_err;
			}
		}
	}

	for (order = SND_SOC_COMP_ORDER_FIRST; order <= SND_SOC_COMP_ORDER_LAST;
			order++) {
		for (i = 0; i < card->num_links; i++) {
			ret = soc_probe_link_dais(card, i, order);
			if (ret < 0) {
				dev_err(card->dev,
					"ASoC: failed to instantiate card %d\n",
					ret);
				goto probe_dai_err;
			}
		}
	}

	for (i = 0; i < card->num_aux_devs; i++) {
		ret = soc_probe_aux_dev(card, i);
		if (ret < 0) {
			dev_err(card->dev,
				"ASoC: failed to add auxiliary devices %d\n",
				ret);
			goto probe_aux_dev_err;
		}
	}

	snd_soc_dapm_link_dai_widgets(card);
	snd_soc_dapm_connect_dai_link_widgets(card);

	if (card->controls)
		snd_soc_add_card_controls(card, card->controls, card->num_controls);

	if (card->dapm_routes)
		snd_soc_dapm_add_routes(&card->dapm, card->dapm_routes,
					card->num_dapm_routes);

	if (card->of_dapm_routes)
		snd_soc_dapm_add_routes(&card->dapm, card->of_dapm_routes,
					card->num_of_dapm_routes);

	snprintf(card->snd_card->shortname, sizeof(card->snd_card->shortname),
		 "%s", card->name);
	snprintf(card->snd_card->longname, sizeof(card->snd_card->longname),
		 "%s", card->long_name ? card->long_name : card->name);
	snprintf(card->snd_card->driver, sizeof(card->snd_card->driver),
		 "%s", card->driver_name ? card->driver_name : card->name);
	for (i = 0; i < ARRAY_SIZE(card->snd_card->driver); i++) {
		switch (card->snd_card->driver[i]) {
		case '_':
		case '-':
		case '\0':
			break;
		default:
			if (!isalnum(card->snd_card->driver[i]))
				card->snd_card->driver[i] = '_';
			break;
		}
	}

	if (card->late_probe) {
		ret = card->late_probe(card);
		if (ret < 0) {
			dev_err(card->dev, "ASoC: %s late_probe() failed: %d\n",
				card->name, ret);
			goto probe_aux_dev_err;
		}
	}

	snd_soc_dapm_new_widgets(card);

	ret = snd_card_register(card->snd_card);
	if (ret < 0) {
		dev_err(card->dev, "ASoC: failed to register soundcard %d\n",
				ret);
		goto probe_aux_dev_err;
	}

	card->instantiated = 1;
	snd_soc_dapm_sync(&card->dapm);
	mutex_unlock(&card->mutex);
	mutex_unlock(&client_mutex);

	return 0;

probe_aux_dev_err:
	for (i = 0; i < card->num_aux_devs; i++)
		soc_remove_aux_dev(card, i);

probe_dai_err:
	soc_remove_dai_links(card);

card_probe_error:
	if (card->remove)
		card->remove(card);

	snd_soc_dapm_free(&card->dapm);
	soc_cleanup_card_debugfs(card);
	snd_card_free(card->snd_card);

base_error:
	mutex_unlock(&card->mutex);
	mutex_unlock(&client_mutex);

	return ret;
}

static int soc_probe(struct platform_device *pdev)
{
	struct snd_soc_card *card = platform_get_drvdata(pdev);

	if (!card)
		return -EINVAL;

	dev_warn(&pdev->dev,
		 "ASoC: machine %s should use snd_soc_register_card()\n",
		 card->name);

	card->dev = &pdev->dev;

	return snd_soc_register_card(card);
}

static int soc_cleanup_card_resources(struct snd_soc_card *card)
{
	int i;

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_pcm_runtime *rtd = &card->rtd[i];
		flush_delayed_work(&rtd->delayed_work);
	}

	for (i = 0; i < card->num_aux_devs; i++)
		soc_remove_aux_dev(card, i);

	soc_remove_dai_links(card);

	soc_cleanup_card_debugfs(card);

	if (card->remove)
		card->remove(card);

	snd_soc_dapm_free(&card->dapm);

	snd_card_free(card->snd_card);
	return 0;

}

static int soc_remove(struct platform_device *pdev)
{
	struct snd_soc_card *card = platform_get_drvdata(pdev);

	snd_soc_unregister_card(card);
	return 0;
}

int snd_soc_poweroff(struct device *dev)
{
	struct snd_soc_card *card = dev_get_drvdata(dev);
	int i;

	if (!card->instantiated)
		return 0;

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_pcm_runtime *rtd = &card->rtd[i];
		flush_delayed_work(&rtd->delayed_work);
	}

	snd_soc_dapm_shutdown(card);

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_pcm_runtime *rtd = &card->rtd[i];
		struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
		int j;

		pinctrl_pm_select_sleep_state(cpu_dai->dev);
		for (j = 0; j < rtd->num_codecs; j++) {
			struct snd_soc_dai *codec_dai = rtd->codec_dais[j];
			pinctrl_pm_select_sleep_state(codec_dai->dev);
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_poweroff);

const struct dev_pm_ops snd_soc_pm_ops = {
	.suspend = snd_soc_suspend,
	.resume = snd_soc_resume,
	.freeze = snd_soc_suspend,
	.thaw = snd_soc_resume,
	.poweroff = snd_soc_poweroff,
	.restore = snd_soc_resume,
};
EXPORT_SYMBOL_GPL(snd_soc_pm_ops);

static struct platform_driver soc_driver = {
	.driver		= {
		.name		= "soc-audio",
		.pm		= &snd_soc_pm_ops,
	},
	.probe		= soc_probe,
	.remove		= soc_remove,
};

struct snd_kcontrol *snd_soc_cnew(const struct snd_kcontrol_new *_template,
				  void *data, const char *long_name,
				  const char *prefix)
{
	struct snd_kcontrol_new template;
	struct snd_kcontrol *kcontrol;
	char *name = NULL;

	memcpy(&template, _template, sizeof(template));
	template.index = 0;

	if (!long_name)
		long_name = template.name;

	if (prefix) {
		name = kasprintf(GFP_KERNEL, "%s %s", prefix, long_name);
		if (!name)
			return NULL;

		template.name = name;
	} else {
		template.name = long_name;
	}

	kcontrol = snd_ctl_new1(&template, data);

	kfree(name);

	return kcontrol;
}
EXPORT_SYMBOL_GPL(snd_soc_cnew);

static int snd_soc_add_controls(struct snd_card *card, struct device *dev,
	const struct snd_kcontrol_new *controls, int num_controls,
	const char *prefix, void *data)
{
	int err, i;

	for (i = 0; i < num_controls; i++) {
		const struct snd_kcontrol_new *control = &controls[i];
		err = snd_ctl_add(card, snd_soc_cnew(control, data,
						     control->name, prefix));
		if (err < 0) {
			dev_err(dev, "ASoC: Failed to add %s: %d\n",
				control->name, err);
			return err;
		}
	}

	return 0;
}

struct snd_kcontrol *snd_soc_card_get_kcontrol(struct snd_soc_card *soc_card,
					       const char *name)
{
	struct snd_card *card = soc_card->snd_card;
	struct snd_kcontrol *kctl;

	if (unlikely(!name))
		return NULL;

	list_for_each_entry(kctl, &card->controls, list)
		if (!strncmp(kctl->id.name, name, sizeof(kctl->id.name)))
			return kctl;
	return NULL;
}
EXPORT_SYMBOL_GPL(snd_soc_card_get_kcontrol);

int snd_soc_add_component_controls(struct snd_soc_component *component,
	const struct snd_kcontrol_new *controls, unsigned int num_controls)
{
	struct snd_card *card = component->card->snd_card;

	return snd_soc_add_controls(card, component->dev, controls,
			num_controls, component->name_prefix, component);
}
EXPORT_SYMBOL_GPL(snd_soc_add_component_controls);

int snd_soc_add_codec_controls(struct snd_soc_codec *codec,
	const struct snd_kcontrol_new *controls, unsigned int num_controls)
{
	return snd_soc_add_component_controls(&codec->component, controls,
		num_controls);
}
EXPORT_SYMBOL_GPL(snd_soc_add_codec_controls);

int snd_soc_add_platform_controls(struct snd_soc_platform *platform,
	const struct snd_kcontrol_new *controls, unsigned int num_controls)
{
	return snd_soc_add_component_controls(&platform->component, controls,
		num_controls);
}
EXPORT_SYMBOL_GPL(snd_soc_add_platform_controls);

int snd_soc_add_card_controls(struct snd_soc_card *soc_card,
	const struct snd_kcontrol_new *controls, int num_controls)
{
	struct snd_card *card = soc_card->snd_card;

	return snd_soc_add_controls(card, soc_card->dev, controls, num_controls,
			NULL, soc_card);
}
EXPORT_SYMBOL_GPL(snd_soc_add_card_controls);

int snd_soc_add_dai_controls(struct snd_soc_dai *dai,
	const struct snd_kcontrol_new *controls, int num_controls)
{
	struct snd_card *card = dai->component->card->snd_card;

	return snd_soc_add_controls(card, dai->dev, controls, num_controls,
			NULL, dai);
}
EXPORT_SYMBOL_GPL(snd_soc_add_dai_controls);

int snd_soc_dai_set_sysclk(struct snd_soc_dai *dai, int clk_id,
	unsigned int freq, int dir)
{
	if (dai->driver && dai->driver->ops->set_sysclk)
		return dai->driver->ops->set_sysclk(dai, clk_id, freq, dir);
	else if (dai->codec && dai->codec->driver->set_sysclk)
		return dai->codec->driver->set_sysclk(dai->codec, clk_id, 0,
						      freq, dir);
	else
		return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(snd_soc_dai_set_sysclk);

int snd_soc_codec_set_sysclk(struct snd_soc_codec *codec, int clk_id,
			     int source, unsigned int freq, int dir)
{
	if (codec->driver->set_sysclk)
		return codec->driver->set_sysclk(codec, clk_id, source,
						 freq, dir);
	else
		return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(snd_soc_codec_set_sysclk);

int snd_soc_dai_set_clkdiv(struct snd_soc_dai *dai,
	int div_id, int div)
{
	if (dai->driver && dai->driver->ops->set_clkdiv)
		return dai->driver->ops->set_clkdiv(dai, div_id, div);
	else
		return -EINVAL;
}
EXPORT_SYMBOL_GPL(snd_soc_dai_set_clkdiv);

int snd_soc_dai_set_pll(struct snd_soc_dai *dai, int pll_id, int source,
	unsigned int freq_in, unsigned int freq_out)
{
	if (dai->driver && dai->driver->ops->set_pll)
		return dai->driver->ops->set_pll(dai, pll_id, source,
					 freq_in, freq_out);
	else if (dai->codec && dai->codec->driver->set_pll)
		return dai->codec->driver->set_pll(dai->codec, pll_id, source,
						   freq_in, freq_out);
	else
		return -EINVAL;
}
EXPORT_SYMBOL_GPL(snd_soc_dai_set_pll);

int snd_soc_codec_set_pll(struct snd_soc_codec *codec, int pll_id, int source,
			  unsigned int freq_in, unsigned int freq_out)
{
	if (codec->driver->set_pll)
		return codec->driver->set_pll(codec, pll_id, source,
					      freq_in, freq_out);
	else
		return -EINVAL;
}
EXPORT_SYMBOL_GPL(snd_soc_codec_set_pll);

int snd_soc_dai_set_bclk_ratio(struct snd_soc_dai *dai, unsigned int ratio)
{
	if (dai->driver && dai->driver->ops->set_bclk_ratio)
		return dai->driver->ops->set_bclk_ratio(dai, ratio);
	else
		return -EINVAL;
}
EXPORT_SYMBOL_GPL(snd_soc_dai_set_bclk_ratio);

int snd_soc_dai_set_fmt(struct snd_soc_dai *dai, unsigned int fmt)
{
	if (dai->driver == NULL)
		return -EINVAL;
	if (dai->driver->ops->set_fmt == NULL)
		return -ENOTSUPP;
	return dai->driver->ops->set_fmt(dai, fmt);
}
EXPORT_SYMBOL_GPL(snd_soc_dai_set_fmt);

static int snd_soc_xlate_tdm_slot_mask(unsigned int slots,
					  unsigned int *tx_mask,
					  unsigned int *rx_mask)
{
	if (*tx_mask || *rx_mask)
		return 0;

	if (!slots)
		return -EINVAL;

	*tx_mask = (1 << slots) - 1;
	*rx_mask = (1 << slots) - 1;

	return 0;
}

int snd_soc_dai_set_tdm_slot(struct snd_soc_dai *dai,
	unsigned int tx_mask, unsigned int rx_mask, int slots, int slot_width)
{
	if (dai->driver && dai->driver->ops->xlate_tdm_slot_mask)
		dai->driver->ops->xlate_tdm_slot_mask(slots,
						&tx_mask, &rx_mask);
	else
		snd_soc_xlate_tdm_slot_mask(slots, &tx_mask, &rx_mask);

	dai->tx_mask = tx_mask;
	dai->rx_mask = rx_mask;

	if (dai->driver && dai->driver->ops->set_tdm_slot)
		return dai->driver->ops->set_tdm_slot(dai, tx_mask, rx_mask,
				slots, slot_width);
	else
		return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(snd_soc_dai_set_tdm_slot);

int snd_soc_dai_set_channel_map(struct snd_soc_dai *dai,
	unsigned int tx_num, unsigned int *tx_slot,
	unsigned int rx_num, unsigned int *rx_slot)
{
	if (dai->driver && dai->driver->ops->set_channel_map)
		return dai->driver->ops->set_channel_map(dai, tx_num, tx_slot,
			rx_num, rx_slot);
	else
		return -EINVAL;
}
EXPORT_SYMBOL_GPL(snd_soc_dai_set_channel_map);

int snd_soc_dai_set_tristate(struct snd_soc_dai *dai, int tristate)
{
	if (dai->driver && dai->driver->ops->set_tristate)
		return dai->driver->ops->set_tristate(dai, tristate);
	else
		return -EINVAL;
}
EXPORT_SYMBOL_GPL(snd_soc_dai_set_tristate);

int snd_soc_dai_digital_mute(struct snd_soc_dai *dai, int mute,
			     int direction)
{
	if (!dai->driver)
		return -ENOTSUPP;

	if (dai->driver->ops->mute_stream)
		return dai->driver->ops->mute_stream(dai, mute, direction);
	else if (direction == SNDRV_PCM_STREAM_PLAYBACK &&
		 dai->driver->ops->digital_mute)
		return dai->driver->ops->digital_mute(dai, mute);
	else
		return -ENOTSUPP;
}
EXPORT_SYMBOL_GPL(snd_soc_dai_digital_mute);

static int snd_soc_init_multicodec(struct snd_soc_card *card,
				   struct snd_soc_dai_link *dai_link)
{
	 
	if (dai_link->codec_name || dai_link->codec_of_node ||
	    dai_link->codec_dai_name) {
		dai_link->num_codecs = 1;

		dai_link->codecs = devm_kzalloc(card->dev,
				sizeof(struct snd_soc_dai_link_component),
				GFP_KERNEL);
		if (!dai_link->codecs)
			return -ENOMEM;

		dai_link->codecs[0].name = dai_link->codec_name;
		dai_link->codecs[0].of_node = dai_link->codec_of_node;
		dai_link->codecs[0].dai_name = dai_link->codec_dai_name;
	}

	if (!dai_link->codecs) {
		dev_err(card->dev, "ASoC: DAI link has no CODECs\n");
		return -EINVAL;
	}

	return 0;
}

int snd_soc_register_card(struct snd_soc_card *card)
{
	int i, j, ret;

	if (!card->name || !card->dev)
		return -EINVAL;

	for (i = 0; i < card->num_links; i++) {
		struct snd_soc_dai_link *link = &card->dai_link[i];

		ret = snd_soc_init_multicodec(card, link);
		if (ret) {
			dev_err(card->dev, "ASoC: failed to init multicodec\n");
			return ret;
		}

		for (j = 0; j < link->num_codecs; j++) {
			 
			if (!!link->codecs[j].name ==
			    !!link->codecs[j].of_node) {
				dev_err(card->dev, "ASoC: Neither/both codec name/of_node are set for %s\n",
					link->name);
				return -EINVAL;
			}
			 
			if (!link->codecs[j].dai_name) {
				dev_err(card->dev, "ASoC: codec_dai_name not set for %s\n",
					link->name);
				return -EINVAL;
			}
		}

		if (link->platform_name && link->platform_of_node) {
			dev_err(card->dev,
				"ASoC: Both platform name/of_node are set for %s\n",
				link->name);
			return -EINVAL;
		}

		if (link->cpu_name && link->cpu_of_node) {
			dev_err(card->dev,
				"ASoC: Neither/both cpu name/of_node are set for %s\n",
				link->name);
			return -EINVAL;
		}
		 
		if (!link->cpu_dai_name &&
		    !(link->cpu_name || link->cpu_of_node)) {
			dev_err(card->dev,
				"ASoC: Neither cpu_dai_name nor cpu_name/of_node are set for %s\n",
				link->name);
			return -EINVAL;
		}
	}

	dev_set_drvdata(card->dev, card);

	snd_soc_initialize_card_lists(card);

	card->rtd = devm_kzalloc(card->dev,
				 sizeof(struct snd_soc_pcm_runtime) *
				 (card->num_links + card->num_aux_devs),
				 GFP_KERNEL);
	if (card->rtd == NULL)
		return -ENOMEM;
	card->num_rtd = 0;
	card->rtd_aux = &card->rtd[card->num_links];

	for (i = 0; i < card->num_links; i++) {
		card->rtd[i].card = card;
		card->rtd[i].dai_link = &card->dai_link[i];
		card->rtd[i].codec_dais = devm_kzalloc(card->dev,
					sizeof(struct snd_soc_dai *) *
					(card->rtd[i].dai_link->num_codecs),
					GFP_KERNEL);
		if (card->rtd[i].codec_dais == NULL)
			return -ENOMEM;
	}

	for (i = 0; i < card->num_aux_devs; i++)
		card->rtd_aux[i].card = card;

	INIT_LIST_HEAD(&card->dapm_dirty);
	INIT_LIST_HEAD(&card->dobj_list);
	card->instantiated = 0;
	mutex_init(&card->mutex);
	mutex_init(&card->dapm_mutex);

	ret = snd_soc_instantiate_card(card);
	if (ret != 0)
		return ret;

	for (i = 0; i < card->num_rtd; i++) {
		struct snd_soc_pcm_runtime *rtd = &card->rtd[i];
		struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
		int j;

		for (j = 0; j < rtd->num_codecs; j++) {
			struct snd_soc_dai *codec_dai = rtd->codec_dais[j];
			if (!codec_dai->active)
				pinctrl_pm_select_sleep_state(codec_dai->dev);
		}

		if (!cpu_dai->active)
			pinctrl_pm_select_sleep_state(cpu_dai->dev);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(snd_soc_register_card);

int snd_soc_unregister_card(struct snd_soc_card *card)
{
	if (card->instantiated) {
		card->instantiated = false;
		snd_soc_dapm_shutdown(card);
		soc_cleanup_card_resources(card);
		dev_dbg(card->dev, "ASoC: Unregistered card '%s'\n", card->name);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_unregister_card);

static char *fmt_single_name(struct device *dev, int *id)
{
	char *found, name[NAME_SIZE];
	int id1, id2;

	if (dev_name(dev) == NULL)
		return NULL;

	strlcpy(name, dev_name(dev), NAME_SIZE);

	found = strstr(name, dev->driver->name);
	if (found) {
		 
		if (sscanf(&found[strlen(dev->driver->name)], ".%d", id) == 1) {

			if (*id == -1)
				found[strlen(dev->driver->name)] = '\0';
		}

	} else {
		 
		if (sscanf(name, "%x-%x", &id1, &id2) == 2) {
			char tmp[NAME_SIZE];

			*id = ((id1 & 0xffff) << 16) + id2;

			snprintf(tmp, NAME_SIZE, "%s.%s", dev->driver->name, name);
			strlcpy(name, tmp, NAME_SIZE);
		} else
			*id = 0;
	}

	return kstrdup(name, GFP_KERNEL);
}

static inline char *fmt_multiple_name(struct device *dev,
		struct snd_soc_dai_driver *dai_drv)
{
	if (dai_drv->name == NULL) {
		dev_err(dev,
			"ASoC: error - multiple DAI %s registered with no name\n",
			dev_name(dev));
		return NULL;
	}

	return kstrdup(dai_drv->name, GFP_KERNEL);
}

static void snd_soc_unregister_dais(struct snd_soc_component *component)
{
	struct snd_soc_dai *dai, *_dai;

	list_for_each_entry_safe(dai, _dai, &component->dai_list, list) {
		dev_dbg(component->dev, "ASoC: Unregistered DAI '%s'\n",
			dai->name);
		list_del(&dai->list);
		kfree(dai->name);
		kfree(dai);
	}
}

static int snd_soc_register_dais(struct snd_soc_component *component,
	struct snd_soc_dai_driver *dai_drv, size_t count,
	bool legacy_dai_naming)
{
	struct device *dev = component->dev;
	struct snd_soc_dai *dai;
	unsigned int i;
	int ret;

	dev_dbg(dev, "ASoC: dai register %s #%Zu\n", dev_name(dev), count);

	component->dai_drv = dai_drv;
	component->num_dai = count;

	for (i = 0; i < count; i++) {

		dai = kzalloc(sizeof(struct snd_soc_dai), GFP_KERNEL);
		if (dai == NULL) {
			ret = -ENOMEM;
			goto err;
		}

		if (count == 1 && legacy_dai_naming &&
			(dai_drv[i].id == 0 || dai_drv[i].name == NULL)) {
			dai->name = fmt_single_name(dev, &dai->id);
		} else {
			dai->name = fmt_multiple_name(dev, &dai_drv[i]);
			if (dai_drv[i].id)
				dai->id = dai_drv[i].id;
			else
				dai->id = i;
		}
		if (dai->name == NULL) {
			kfree(dai);
			ret = -ENOMEM;
			goto err;
		}

		dai->component = component;
		dai->dev = dev;
		dai->driver = &dai_drv[i];
		if (!dai->driver->ops)
			dai->driver->ops = &null_dai_ops;

		list_add(&dai->list, &component->dai_list);

		dev_dbg(dev, "ASoC: Registered DAI '%s'\n", dai->name);
	}

	return 0;

err:
	snd_soc_unregister_dais(component);

	return ret;
}

static void snd_soc_component_seq_notifier(struct snd_soc_dapm_context *dapm,
	enum snd_soc_dapm_type type, int subseq)
{
	struct snd_soc_component *component = dapm->component;

	component->driver->seq_notifier(component, type, subseq);
}

static int snd_soc_component_stream_event(struct snd_soc_dapm_context *dapm,
	int event)
{
	struct snd_soc_component *component = dapm->component;

	return component->driver->stream_event(component, event);
}

static int snd_soc_component_initialize(struct snd_soc_component *component,
	const struct snd_soc_component_driver *driver, struct device *dev)
{
	struct snd_soc_dapm_context *dapm;

	component->name = fmt_single_name(dev, &component->id);
	if (!component->name) {
		dev_err(dev, "ASoC: Failed to allocate name\n");
		return -ENOMEM;
	}

	component->dev = dev;
	component->driver = driver;
	component->probe = component->driver->probe;
	component->remove = component->driver->remove;

	dapm = &component->dapm;
	dapm->dev = dev;
	dapm->component = component;
	dapm->bias_level = SND_SOC_BIAS_OFF;
	dapm->idle_bias_off = true;
	if (driver->seq_notifier)
		dapm->seq_notifier = snd_soc_component_seq_notifier;
	if (driver->stream_event)
		dapm->stream_event = snd_soc_component_stream_event;

	component->controls = driver->controls;
	component->num_controls = driver->num_controls;
	component->dapm_widgets = driver->dapm_widgets;
	component->num_dapm_widgets = driver->num_dapm_widgets;
	component->dapm_routes = driver->dapm_routes;
	component->num_dapm_routes = driver->num_dapm_routes;

	INIT_LIST_HEAD(&component->dai_list);
	mutex_init(&component->io_mutex);

	return 0;
}

static void snd_soc_component_setup_regmap(struct snd_soc_component *component)
{
	int val_bytes = regmap_get_val_bytes(component->regmap);

	if (val_bytes > 0)
		component->val_bytes = val_bytes;
}

#ifdef CONFIG_REGMAP

void snd_soc_component_init_regmap(struct snd_soc_component *component,
	struct regmap *regmap)
{
	component->regmap = regmap;
	snd_soc_component_setup_regmap(component);
}
EXPORT_SYMBOL_GPL(snd_soc_component_init_regmap);

void snd_soc_component_exit_regmap(struct snd_soc_component *component)
{
	regmap_exit(component->regmap);
	component->regmap = NULL;
}
EXPORT_SYMBOL_GPL(snd_soc_component_exit_regmap);

#endif

static void snd_soc_component_add_unlocked(struct snd_soc_component *component)
{
	if (!component->write && !component->read) {
		if (!component->regmap)
			component->regmap = dev_get_regmap(component->dev, NULL);
		if (component->regmap)
			snd_soc_component_setup_regmap(component);
	}

	list_add(&component->list, &component_list);
	INIT_LIST_HEAD(&component->dobj_list);
}

static void snd_soc_component_add(struct snd_soc_component *component)
{
	mutex_lock(&client_mutex);
	snd_soc_component_add_unlocked(component);
	mutex_unlock(&client_mutex);
}

static void snd_soc_component_cleanup(struct snd_soc_component *component)
{
	snd_soc_unregister_dais(component);
	kfree(component->name);
}

static void snd_soc_component_del_unlocked(struct snd_soc_component *component)
{
	list_del(&component->list);
}

int snd_soc_register_component(struct device *dev,
			       const struct snd_soc_component_driver *cmpnt_drv,
			       struct snd_soc_dai_driver *dai_drv,
			       int num_dai)
{
	struct snd_soc_component *cmpnt;
	int ret;

	cmpnt = kzalloc(sizeof(*cmpnt), GFP_KERNEL);
	if (!cmpnt) {
		dev_err(dev, "ASoC: Failed to allocate memory\n");
		return -ENOMEM;
	}

	ret = snd_soc_component_initialize(cmpnt, cmpnt_drv, dev);
	if (ret)
		goto err_free;

	cmpnt->ignore_pmdown_time = true;
	cmpnt->registered_as_component = true;

	ret = snd_soc_register_dais(cmpnt, dai_drv, num_dai, true);
	if (ret < 0) {
		dev_err(dev, "ASoC: Failed to register DAIs: %d\n", ret);
		goto err_cleanup;
	}

	snd_soc_component_add(cmpnt);

	return 0;

err_cleanup:
	snd_soc_component_cleanup(cmpnt);
err_free:
	kfree(cmpnt);
	return ret;
}
EXPORT_SYMBOL_GPL(snd_soc_register_component);

void snd_soc_unregister_component(struct device *dev)
{
	struct snd_soc_component *cmpnt;

	mutex_lock(&client_mutex);
	list_for_each_entry(cmpnt, &component_list, list) {
		if (dev == cmpnt->dev && cmpnt->registered_as_component)
			goto found;
	}
	mutex_unlock(&client_mutex);
	return;

found:
	snd_soc_tplg_component_remove(cmpnt, SND_SOC_TPLG_INDEX_ALL);
	snd_soc_component_del_unlocked(cmpnt);
	mutex_unlock(&client_mutex);
	snd_soc_component_cleanup(cmpnt);
	kfree(cmpnt);
}
EXPORT_SYMBOL_GPL(snd_soc_unregister_component);

static int snd_soc_platform_drv_probe(struct snd_soc_component *component)
{
	struct snd_soc_platform *platform = snd_soc_component_to_platform(component);

	return platform->driver->probe(platform);
}

static void snd_soc_platform_drv_remove(struct snd_soc_component *component)
{
	struct snd_soc_platform *platform = snd_soc_component_to_platform(component);

	platform->driver->remove(platform);
}

int snd_soc_add_platform(struct device *dev, struct snd_soc_platform *platform,
		const struct snd_soc_platform_driver *platform_drv)
{
	int ret;

	ret = snd_soc_component_initialize(&platform->component,
			&platform_drv->component_driver, dev);
	if (ret)
		return ret;

	platform->dev = dev;
	platform->driver = platform_drv;

	if (platform_drv->probe)
		platform->component.probe = snd_soc_platform_drv_probe;
	if (platform_drv->remove)
		platform->component.remove = snd_soc_platform_drv_remove;

#ifdef CONFIG_DEBUG_FS
	platform->component.debugfs_prefix = "platform";
#endif

	mutex_lock(&client_mutex);
	snd_soc_component_add_unlocked(&platform->component);
	list_add(&platform->list, &platform_list);
	mutex_unlock(&client_mutex);

	dev_dbg(dev, "ASoC: Registered platform '%s'\n",
		platform->component.name);

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_add_platform);

int snd_soc_register_platform(struct device *dev,
		const struct snd_soc_platform_driver *platform_drv)
{
	struct snd_soc_platform *platform;
	int ret;

	dev_dbg(dev, "ASoC: platform register %s\n", dev_name(dev));

	platform = kzalloc(sizeof(struct snd_soc_platform), GFP_KERNEL);
	if (platform == NULL)
		return -ENOMEM;

	ret = snd_soc_add_platform(dev, platform, platform_drv);
	if (ret)
		kfree(platform);

	return ret;
}
EXPORT_SYMBOL_GPL(snd_soc_register_platform);

void snd_soc_remove_platform(struct snd_soc_platform *platform)
{

	mutex_lock(&client_mutex);
	list_del(&platform->list);
	snd_soc_component_del_unlocked(&platform->component);
	mutex_unlock(&client_mutex);

	dev_dbg(platform->dev, "ASoC: Unregistered platform '%s'\n",
		platform->component.name);

	snd_soc_component_cleanup(&platform->component);
}
EXPORT_SYMBOL_GPL(snd_soc_remove_platform);

struct snd_soc_platform *snd_soc_lookup_platform(struct device *dev)
{
	struct snd_soc_platform *platform;

	mutex_lock(&client_mutex);
	list_for_each_entry(platform, &platform_list, list) {
		if (dev == platform->dev) {
			mutex_unlock(&client_mutex);
			return platform;
		}
	}
	mutex_unlock(&client_mutex);

	return NULL;
}
EXPORT_SYMBOL_GPL(snd_soc_lookup_platform);

void snd_soc_unregister_platform(struct device *dev)
{
	struct snd_soc_platform *platform;

	platform = snd_soc_lookup_platform(dev);
	if (!platform)
		return;

	snd_soc_remove_platform(platform);
	kfree(platform);
}
EXPORT_SYMBOL_GPL(snd_soc_unregister_platform);

static u64 codec_format_map[] = {
	SNDRV_PCM_FMTBIT_S16_LE | SNDRV_PCM_FMTBIT_S16_BE,
	SNDRV_PCM_FMTBIT_U16_LE | SNDRV_PCM_FMTBIT_U16_BE,
	SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S24_BE,
	SNDRV_PCM_FMTBIT_U24_LE | SNDRV_PCM_FMTBIT_U24_BE,
	SNDRV_PCM_FMTBIT_S32_LE | SNDRV_PCM_FMTBIT_S32_BE,
	SNDRV_PCM_FMTBIT_U32_LE | SNDRV_PCM_FMTBIT_U32_BE,
	SNDRV_PCM_FMTBIT_S24_3LE | SNDRV_PCM_FMTBIT_U24_3BE,
	SNDRV_PCM_FMTBIT_U24_3LE | SNDRV_PCM_FMTBIT_U24_3BE,
	SNDRV_PCM_FMTBIT_S20_3LE | SNDRV_PCM_FMTBIT_S20_3BE,
	SNDRV_PCM_FMTBIT_U20_3LE | SNDRV_PCM_FMTBIT_U20_3BE,
	SNDRV_PCM_FMTBIT_S18_3LE | SNDRV_PCM_FMTBIT_S18_3BE,
	SNDRV_PCM_FMTBIT_U18_3LE | SNDRV_PCM_FMTBIT_U18_3BE,
	SNDRV_PCM_FMTBIT_FLOAT_LE | SNDRV_PCM_FMTBIT_FLOAT_BE,
	SNDRV_PCM_FMTBIT_FLOAT64_LE | SNDRV_PCM_FMTBIT_FLOAT64_BE,
	SNDRV_PCM_FMTBIT_IEC958_SUBFRAME_LE
	| SNDRV_PCM_FMTBIT_IEC958_SUBFRAME_BE,
};

static void fixup_codec_formats(struct snd_soc_pcm_stream *stream)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(codec_format_map); i++)
		if (stream->formats & codec_format_map[i])
			stream->formats |= codec_format_map[i];
}

static int snd_soc_codec_drv_probe(struct snd_soc_component *component)
{
	struct snd_soc_codec *codec = snd_soc_component_to_codec(component);

	return codec->driver->probe(codec);
}

static void snd_soc_codec_drv_remove(struct snd_soc_component *component)
{
	struct snd_soc_codec *codec = snd_soc_component_to_codec(component);

	codec->driver->remove(codec);
}

static int snd_soc_codec_drv_write(struct snd_soc_component *component,
	unsigned int reg, unsigned int val)
{
	struct snd_soc_codec *codec = snd_soc_component_to_codec(component);

	return codec->driver->write(codec, reg, val);
}

static int snd_soc_codec_drv_read(struct snd_soc_component *component,
	unsigned int reg, unsigned int *val)
{
	struct snd_soc_codec *codec = snd_soc_component_to_codec(component);

	*val = codec->driver->read(codec, reg);

	return 0;
}

static int snd_soc_codec_set_bias_level(struct snd_soc_dapm_context *dapm,
	enum snd_soc_bias_level level)
{
	struct snd_soc_codec *codec = snd_soc_dapm_to_codec(dapm);

	return codec->driver->set_bias_level(codec, level);
}

int snd_soc_register_codec(struct device *dev,
			   const struct snd_soc_codec_driver *codec_drv,
			   struct snd_soc_dai_driver *dai_drv,
			   int num_dai)
{
	struct snd_soc_dapm_context *dapm;
	struct snd_soc_codec *codec;
	struct snd_soc_dai *dai;
	int ret, i;

	dev_dbg(dev, "codec register %s\n", dev_name(dev));

	codec = kzalloc(sizeof(struct snd_soc_codec), GFP_KERNEL);
	if (codec == NULL)
		return -ENOMEM;

	codec->component.codec = codec;

	ret = snd_soc_component_initialize(&codec->component,
			&codec_drv->component_driver, dev);
	if (ret)
		goto err_free;

	if (codec_drv->controls) {
		codec->component.controls = codec_drv->controls;
		codec->component.num_controls = codec_drv->num_controls;
	}
	if (codec_drv->dapm_widgets) {
		codec->component.dapm_widgets = codec_drv->dapm_widgets;
		codec->component.num_dapm_widgets = codec_drv->num_dapm_widgets;
	}
	if (codec_drv->dapm_routes) {
		codec->component.dapm_routes = codec_drv->dapm_routes;
		codec->component.num_dapm_routes = codec_drv->num_dapm_routes;
	}

	if (codec_drv->probe)
		codec->component.probe = snd_soc_codec_drv_probe;
	if (codec_drv->remove)
		codec->component.remove = snd_soc_codec_drv_remove;
	if (codec_drv->write)
		codec->component.write = snd_soc_codec_drv_write;
	if (codec_drv->read)
		codec->component.read = snd_soc_codec_drv_read;
	codec->component.ignore_pmdown_time = codec_drv->ignore_pmdown_time;

	dapm = snd_soc_codec_get_dapm(codec);
	dapm->idle_bias_off = codec_drv->idle_bias_off;
	dapm->suspend_bias_off = codec_drv->suspend_bias_off;
	if (codec_drv->seq_notifier)
		dapm->seq_notifier = codec_drv->seq_notifier;
	if (codec_drv->set_bias_level)
		dapm->set_bias_level = snd_soc_codec_set_bias_level;
	codec->dev = dev;
	codec->driver = codec_drv;
	codec->component.val_bytes = codec_drv->reg_word_size;

#ifdef CONFIG_DEBUG_FS
	codec->component.init_debugfs = soc_init_codec_debugfs;
	codec->component.debugfs_prefix = "codec";
#endif

	if (codec_drv->get_regmap)
		codec->component.regmap = codec_drv->get_regmap(dev);

	for (i = 0; i < num_dai; i++) {
		fixup_codec_formats(&dai_drv[i].playback);
		fixup_codec_formats(&dai_drv[i].capture);
	}

	ret = snd_soc_register_dais(&codec->component, dai_drv, num_dai, false);
	if (ret < 0) {
		dev_err(dev, "ASoC: Failed to register DAIs: %d\n", ret);
		goto err_cleanup;
	}

	list_for_each_entry(dai, &codec->component.dai_list, list)
		dai->codec = codec;

	mutex_lock(&client_mutex);
	snd_soc_component_add_unlocked(&codec->component);
	list_add(&codec->list, &codec_list);
	mutex_unlock(&client_mutex);

	dev_dbg(codec->dev, "ASoC: Registered codec '%s'\n",
		codec->component.name);
	return 0;

err_cleanup:
	snd_soc_component_cleanup(&codec->component);
err_free:
	kfree(codec);
	return ret;
}
EXPORT_SYMBOL_GPL(snd_soc_register_codec);

void snd_soc_unregister_codec(struct device *dev)
{
	struct snd_soc_codec *codec;

	mutex_lock(&client_mutex);
	list_for_each_entry(codec, &codec_list, list) {
		if (dev == codec->dev)
			goto found;
	}
	mutex_unlock(&client_mutex);
	return;

found:
	list_del(&codec->list);
	snd_soc_component_del_unlocked(&codec->component);
	mutex_unlock(&client_mutex);

	dev_dbg(codec->dev, "ASoC: Unregistered codec '%s'\n",
			codec->component.name);

	snd_soc_component_cleanup(&codec->component);
	snd_soc_cache_exit(codec);
	kfree(codec);
}
EXPORT_SYMBOL_GPL(snd_soc_unregister_codec);

int snd_soc_of_parse_card_name(struct snd_soc_card *card,
			       const char *propname)
{
	struct device_node *np;
	int ret;

	if (!card->dev) {
		pr_err("card->dev is not set before calling %s\n", __func__);
		return -EINVAL;
	}

	np = card->dev->of_node;

	ret = of_property_read_string_index(np, propname, 0, &card->name);
	 
	if (ret < 0 && ret != -EINVAL) {
		dev_err(card->dev,
			"ASoC: Property '%s' could not be read: %d\n",
			propname, ret);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_of_parse_card_name);

static const struct snd_soc_dapm_widget simple_widgets[] = {
	SND_SOC_DAPM_MIC("Microphone", NULL),
	SND_SOC_DAPM_LINE("Line", NULL),
	SND_SOC_DAPM_HP("Headphone", NULL),
	SND_SOC_DAPM_SPK("Speaker", NULL),
};

int snd_soc_of_parse_audio_simple_widgets(struct snd_soc_card *card,
					  const char *propname)
{
	struct device_node *np = card->dev->of_node;
	struct snd_soc_dapm_widget *widgets;
	const char *template, *wname;
	int i, j, num_widgets, ret;

	num_widgets = of_property_count_strings(np, propname);
	if (num_widgets < 0) {
		dev_err(card->dev,
			"ASoC: Property '%s' does not exist\n",	propname);
		return -EINVAL;
	}
	if (num_widgets & 1) {
		dev_err(card->dev,
			"ASoC: Property '%s' length is not even\n", propname);
		return -EINVAL;
	}

	num_widgets /= 2;
	if (!num_widgets) {
		dev_err(card->dev, "ASoC: Property '%s's length is zero\n",
			propname);
		return -EINVAL;
	}

	widgets = devm_kcalloc(card->dev, num_widgets, sizeof(*widgets),
			       GFP_KERNEL);
	if (!widgets) {
		dev_err(card->dev,
			"ASoC: Could not allocate memory for widgets\n");
		return -ENOMEM;
	}

	for (i = 0; i < num_widgets; i++) {
		ret = of_property_read_string_index(np, propname,
			2 * i, &template);
		if (ret) {
			dev_err(card->dev,
				"ASoC: Property '%s' index %d read error:%d\n",
				propname, 2 * i, ret);
			return -EINVAL;
		}

		for (j = 0; j < ARRAY_SIZE(simple_widgets); j++) {
			if (!strncmp(template, simple_widgets[j].name,
				     strlen(simple_widgets[j].name))) {
				widgets[i] = simple_widgets[j];
				break;
			}
		}

		if (j >= ARRAY_SIZE(simple_widgets)) {
			dev_err(card->dev,
				"ASoC: DAPM widget '%s' is not supported\n",
				template);
			return -EINVAL;
		}

		ret = of_property_read_string_index(np, propname,
						    (2 * i) + 1,
						    &wname);
		if (ret) {
			dev_err(card->dev,
				"ASoC: Property '%s' index %d read error:%d\n",
				propname, (2 * i) + 1, ret);
			return -EINVAL;
		}

		widgets[i].name = wname;
	}

	card->of_dapm_widgets = widgets;
	card->num_of_dapm_widgets = num_widgets;

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_of_parse_audio_simple_widgets);

static int snd_soc_of_get_slot_mask(struct device_node *np,
				    const char *prop_name,
				    unsigned int *mask)
{
	u32 val;
	const __be32 *of_slot_mask = of_get_property(np, prop_name, &val);
	int i;

	if (!of_slot_mask)
		return 0;
	val /= sizeof(u32);
	for (i = 0; i < val; i++)
		if (be32_to_cpup(&of_slot_mask[i]))
			*mask |= (1 << i);

	return val;
}

int snd_soc_of_parse_tdm_slot(struct device_node *np,
			      unsigned int *tx_mask,
			      unsigned int *rx_mask,
			      unsigned int *slots,
			      unsigned int *slot_width)
{
	u32 val;
	int ret;

	if (tx_mask)
		snd_soc_of_get_slot_mask(np, "dai-tdm-slot-tx-mask", tx_mask);
	if (rx_mask)
		snd_soc_of_get_slot_mask(np, "dai-tdm-slot-rx-mask", rx_mask);

	if (of_property_read_bool(np, "dai-tdm-slot-num")) {
		ret = of_property_read_u32(np, "dai-tdm-slot-num", &val);
		if (ret)
			return ret;

		if (slots)
			*slots = val;
	}

	if (of_property_read_bool(np, "dai-tdm-slot-width")) {
		ret = of_property_read_u32(np, "dai-tdm-slot-width", &val);
		if (ret)
			return ret;

		if (slot_width)
			*slot_width = val;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_of_parse_tdm_slot);

void snd_soc_of_parse_audio_prefix(struct snd_soc_card *card,
				   struct snd_soc_codec_conf *codec_conf,
				   struct device_node *of_node,
				   const char *propname)
{
	struct device_node *np = card->dev->of_node;
	const char *str;
	int ret;

	ret = of_property_read_string(np, propname, &str);
	if (ret < 0) {
		 
		return;
	}

	codec_conf->of_node	= of_node;
	codec_conf->name_prefix	= str;
}
EXPORT_SYMBOL_GPL(snd_soc_of_parse_audio_prefix);

int snd_soc_of_parse_audio_routing(struct snd_soc_card *card,
				   const char *propname)
{
	struct device_node *np = card->dev->of_node;
	int num_routes;
	struct snd_soc_dapm_route *routes;
	int i, ret;

	num_routes = of_property_count_strings(np, propname);
	if (num_routes < 0 || num_routes & 1) {
		dev_err(card->dev,
			"ASoC: Property '%s' does not exist or its length is not even\n",
			propname);
		return -EINVAL;
	}
	num_routes /= 2;
	if (!num_routes) {
		dev_err(card->dev, "ASoC: Property '%s's length is zero\n",
			propname);
		return -EINVAL;
	}

	routes = devm_kzalloc(card->dev, num_routes * sizeof(*routes),
			      GFP_KERNEL);
	if (!routes) {
		dev_err(card->dev,
			"ASoC: Could not allocate DAPM route table\n");
		return -EINVAL;
	}

	for (i = 0; i < num_routes; i++) {
		ret = of_property_read_string_index(np, propname,
			2 * i, &routes[i].sink);
		if (ret) {
			dev_err(card->dev,
				"ASoC: Property '%s' index %d could not be read: %d\n",
				propname, 2 * i, ret);
			return -EINVAL;
		}
		ret = of_property_read_string_index(np, propname,
			(2 * i) + 1, &routes[i].source);
		if (ret) {
			dev_err(card->dev,
				"ASoC: Property '%s' index %d could not be read: %d\n",
				propname, (2 * i) + 1, ret);
			return -EINVAL;
		}
	}

	card->num_of_dapm_routes = num_routes;
	card->of_dapm_routes = routes;

	return 0;
}
EXPORT_SYMBOL_GPL(snd_soc_of_parse_audio_routing);

unsigned int snd_soc_of_parse_daifmt(struct device_node *np,
				     const char *prefix,
				     struct device_node **bitclkmaster,
				     struct device_node **framemaster)
{
	int ret, i;
	char prop[128];
	unsigned int format = 0;
	int bit, frame;
	const char *str;
	struct {
		char *name;
		unsigned int val;
	} of_fmt_table[] = {
		{ "i2s",	SND_SOC_DAIFMT_I2S },
		{ "right_j",	SND_SOC_DAIFMT_RIGHT_J },
		{ "left_j",	SND_SOC_DAIFMT_LEFT_J },
		{ "dsp_a",	SND_SOC_DAIFMT_DSP_A },
		{ "dsp_b",	SND_SOC_DAIFMT_DSP_B },
		{ "ac97",	SND_SOC_DAIFMT_AC97 },
		{ "pdm",	SND_SOC_DAIFMT_PDM},
		{ "msb",	SND_SOC_DAIFMT_MSB },
		{ "lsb",	SND_SOC_DAIFMT_LSB },
	};

	if (!prefix)
		prefix = "";

	snprintf(prop, sizeof(prop), "%sformat", prefix);
	ret = of_property_read_string(np, prop, &str);
	if (ret == 0) {
		for (i = 0; i < ARRAY_SIZE(of_fmt_table); i++) {
			if (strcmp(str, of_fmt_table[i].name) == 0) {
				format |= of_fmt_table[i].val;
				break;
			}
		}
	}

	snprintf(prop, sizeof(prop), "%scontinuous-clock", prefix);
	if (of_get_property(np, prop, NULL))
		format |= SND_SOC_DAIFMT_CONT;
	else
		format |= SND_SOC_DAIFMT_GATED;

	snprintf(prop, sizeof(prop), "%sbitclock-inversion", prefix);
	bit = !!of_get_property(np, prop, NULL);

	snprintf(prop, sizeof(prop), "%sframe-inversion", prefix);
	frame = !!of_get_property(np, prop, NULL);

	switch ((bit << 4) + frame) {
	case 0x11:
		format |= SND_SOC_DAIFMT_IB_IF;
		break;
	case 0x10:
		format |= SND_SOC_DAIFMT_IB_NF;
		break;
	case 0x01:
		format |= SND_SOC_DAIFMT_NB_IF;
		break;
	default:
		 
		break;
	}

	snprintf(prop, sizeof(prop), "%sbitclock-master", prefix);
	bit = !!of_get_property(np, prop, NULL);
	if (bit && bitclkmaster)
		*bitclkmaster = of_parse_phandle(np, prop, 0);

	snprintf(prop, sizeof(prop), "%sframe-master", prefix);
	frame = !!of_get_property(np, prop, NULL);
	if (frame && framemaster)
		*framemaster = of_parse_phandle(np, prop, 0);

	switch ((bit << 4) + frame) {
	case 0x11:
		format |= SND_SOC_DAIFMT_CBM_CFM;
		break;
	case 0x10:
		format |= SND_SOC_DAIFMT_CBM_CFS;
		break;
	case 0x01:
		format |= SND_SOC_DAIFMT_CBS_CFM;
		break;
	default:
		format |= SND_SOC_DAIFMT_CBS_CFS;
		break;
	}

	return format;
}
EXPORT_SYMBOL_GPL(snd_soc_of_parse_daifmt);

static int snd_soc_get_dai_name(struct of_phandle_args *args,
				const char **dai_name)
{
	struct snd_soc_component *pos;
	struct device_node *component_of_node;
	int ret = -EPROBE_DEFER;

	mutex_lock(&client_mutex);
	list_for_each_entry(pos, &component_list, list) {
		component_of_node = pos->dev->of_node;
		if (!component_of_node && pos->dev->parent)
			component_of_node = pos->dev->parent->of_node;

		if (component_of_node != args->np)
			continue;

		if (pos->driver->of_xlate_dai_name) {
			ret = pos->driver->of_xlate_dai_name(pos,
							     args,
							     dai_name);
		} else {
			int id = -1;

			switch (args->args_count) {
			case 0:
				id = 0;  
				break;
			case 1:
				id = args->args[0];
				break;
			default:
				 
				break;
			}

			if (id < 0 || id >= pos->num_dai) {
				ret = -EINVAL;
				continue;
			}

			ret = 0;

			*dai_name = pos->dai_drv[id].name;
			if (!*dai_name)
				*dai_name = pos->name;
		}

		break;
	}
	mutex_unlock(&client_mutex);
	return ret;
}

int snd_soc_of_get_dai_name(struct device_node *of_node,
			    const char **dai_name)
{
	struct of_phandle_args args;
	int ret;

	ret = of_parse_phandle_with_args(of_node, "sound-dai",
					 "#sound-dai-cells", 0, &args);
	if (ret)
		return ret;

	ret = snd_soc_get_dai_name(&args, dai_name);

	of_node_put(args.np);

	return ret;
}
EXPORT_SYMBOL_GPL(snd_soc_of_get_dai_name);

int snd_soc_of_get_dai_link_codecs(struct device *dev,
				   struct device_node *of_node,
				   struct snd_soc_dai_link *dai_link)
{
	struct of_phandle_args args;
	struct snd_soc_dai_link_component *component;
	char *name;
	int index, num_codecs, ret;

	name = "sound-dai";
	num_codecs = of_count_phandle_with_args(of_node, name,
						"#sound-dai-cells");
	if (num_codecs <= 0) {
		if (num_codecs == -ENOENT)
			dev_err(dev, "No 'sound-dai' property\n");
		else
			dev_err(dev, "Bad phandle in 'sound-dai'\n");
		return num_codecs;
	}
	component = devm_kzalloc(dev,
				 sizeof *component * num_codecs,
				 GFP_KERNEL);
	if (!component)
		return -ENOMEM;
	dai_link->codecs = component;
	dai_link->num_codecs = num_codecs;

	for (index = 0, component = dai_link->codecs;
	     index < dai_link->num_codecs;
	     index++, component++) {
		ret = of_parse_phandle_with_args(of_node, name,
						 "#sound-dai-cells",
						  index, &args);
		if (ret)
			goto err;
		component->of_node = args.np;
		ret = snd_soc_get_dai_name(&args, &component->dai_name);
		if (ret < 0)
			goto err;
	}
	return 0;
err:
	for (index = 0, component = dai_link->codecs;
	     index < dai_link->num_codecs;
	     index++, component++) {
		if (!component->of_node)
			break;
		of_node_put(component->of_node);
		component->of_node = NULL;
	}
	dai_link->codecs = NULL;
	dai_link->num_codecs = 0;
	return ret;
}
EXPORT_SYMBOL_GPL(snd_soc_of_get_dai_link_codecs);

static int __init snd_soc_init(void)
{
	snd_soc_debugfs_init();
	snd_soc_util_init();

	return platform_driver_register(&soc_driver);
}
module_init(snd_soc_init);

static void __exit snd_soc_exit(void)
{
	snd_soc_util_exit();
	snd_soc_debugfs_exit();

	platform_driver_unregister(&soc_driver);
}
module_exit(snd_soc_exit);

MODULE_AUTHOR("Liam Girdwood, lrg@slimlogic.co.uk");
MODULE_DESCRIPTION("ALSA SoC Core");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:soc-audio");
