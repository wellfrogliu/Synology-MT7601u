#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/i2c.h>
#include <linux/spi/spi.h>
#if defined(MY_ABC_HERE)
#else  
#include <linux/regmap.h>
#endif  
#include <linux/export.h>
#include <sound/soc.h>

int snd_soc_component_read(struct snd_soc_component *component,
	unsigned int reg, unsigned int *val)
{
	int ret;

	if (component->regmap)
		ret = regmap_read(component->regmap, reg, val);
	else if (component->read)
		ret = component->read(component, reg, val);
	else
		ret = -EIO;

	return ret;
}
EXPORT_SYMBOL_GPL(snd_soc_component_read);

int snd_soc_component_write(struct snd_soc_component *component,
	unsigned int reg, unsigned int val)
{
	if (component->regmap)
		return regmap_write(component->regmap, reg, val);
	else if (component->write)
		return component->write(component, reg, val);
	else
		return -EIO;
}
EXPORT_SYMBOL_GPL(snd_soc_component_write);

static int snd_soc_component_update_bits_legacy(
	struct snd_soc_component *component, unsigned int reg,
	unsigned int mask, unsigned int val, bool *change)
{
	unsigned int old, new;
	int ret;

	if (!component->read || !component->write)
		return -EIO;

	mutex_lock(&component->io_mutex);

	ret = component->read(component, reg, &old);
	if (ret < 0)
		goto out_unlock;

	new = (old & ~mask) | (val & mask);
	*change = old != new;
	if (*change)
		ret = component->write(component, reg, new);
out_unlock:
	mutex_unlock(&component->io_mutex);

	return ret;
}

int snd_soc_component_update_bits(struct snd_soc_component *component,
	unsigned int reg, unsigned int mask, unsigned int val)
{
	bool change;
	int ret;

	if (component->regmap)
		ret = regmap_update_bits_check(component->regmap, reg, mask,
			val, &change);
	else
		ret = snd_soc_component_update_bits_legacy(component, reg,
			mask, val, &change);

	if (ret < 0)
		return ret;
	return change;
}
EXPORT_SYMBOL_GPL(snd_soc_component_update_bits);

int snd_soc_component_update_bits_async(struct snd_soc_component *component,
	unsigned int reg, unsigned int mask, unsigned int val)
{
	bool change;
	int ret;

	if (component->regmap)
		ret = regmap_update_bits_check_async(component->regmap, reg,
			mask, val, &change);
	else
		ret = snd_soc_component_update_bits_legacy(component, reg,
			mask, val, &change);

	if (ret < 0)
		return ret;
	return change;
}
EXPORT_SYMBOL_GPL(snd_soc_component_update_bits_async);

void snd_soc_component_async_complete(struct snd_soc_component *component)
{
	if (component->regmap)
		regmap_async_complete(component->regmap);
}
EXPORT_SYMBOL_GPL(snd_soc_component_async_complete);

int snd_soc_component_test_bits(struct snd_soc_component *component,
	unsigned int reg, unsigned int mask, unsigned int value)
{
	unsigned int old, new;
	int ret;

	ret = snd_soc_component_read(component, reg, &old);
	if (ret < 0)
		return ret;
	new = (old & ~mask) | value;
	return old != new;
}
EXPORT_SYMBOL_GPL(snd_soc_component_test_bits);

unsigned int snd_soc_read(struct snd_soc_codec *codec, unsigned int reg)
{
	unsigned int val;
	int ret;

	ret = snd_soc_component_read(&codec->component, reg, &val);
	if (ret < 0)
		return -1;

	return val;
}
EXPORT_SYMBOL_GPL(snd_soc_read);

int snd_soc_write(struct snd_soc_codec *codec, unsigned int reg,
	unsigned int val)
{
	return snd_soc_component_write(&codec->component, reg, val);
}
EXPORT_SYMBOL_GPL(snd_soc_write);

int snd_soc_update_bits(struct snd_soc_codec *codec, unsigned int reg,
				unsigned int mask, unsigned int value)
{
	return snd_soc_component_update_bits(&codec->component, reg, mask,
		value);
}
EXPORT_SYMBOL_GPL(snd_soc_update_bits);

int snd_soc_test_bits(struct snd_soc_codec *codec, unsigned int reg,
				unsigned int mask, unsigned int value)
{
	return snd_soc_component_test_bits(&codec->component, reg, mask, value);
}
EXPORT_SYMBOL_GPL(snd_soc_test_bits);

int snd_soc_platform_read(struct snd_soc_platform *platform,
					unsigned int reg)
{
	unsigned int val;
	int ret;

	ret = snd_soc_component_read(&platform->component, reg, &val);
	if (ret < 0)
		return -1;

	return val;
}
EXPORT_SYMBOL_GPL(snd_soc_platform_read);

int snd_soc_platform_write(struct snd_soc_platform *platform,
					 unsigned int reg, unsigned int val)
{
	return snd_soc_component_write(&platform->component, reg, val);
}
EXPORT_SYMBOL_GPL(snd_soc_platform_write);
